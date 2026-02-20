"""
CTF Manager — Flask web app that manages per-team Docker CTF instances.

Environment variables (set in manager/docker-compose.yaml):
  ADMIN_TOKEN       — token required to access /admin routes
  CTF_COMPOSE_FILE  — compose file path inside the manager container
  CHALLENGE_DIR     — absolute host path to challenge/ (for --project-directory)
  SECRET_KEY        — Flask session signing key
  PORT_RANGE_START  — first port to assign to teams (default 8000)
  HOST_IP           — IP / hostname shown to teams in their dashboard URL
  FLAG_INSPECTED, FLAG_LOGIN, FLAG_CREDENTIAL_HARVESTER,
  FLAG_ADMIN_ACCESS, FLAG_FILE_UPLOAD — correct flag values for submission scoring
"""

import hashlib
import hmac
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

import bcrypt
from flask import (Flask, flash, redirect, render_template,
                   request, session, url_for)

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

ADMIN_TOKEN      = os.environ.get('ADMIN_TOKEN', '')
# Path the compose CLIENT reads (inside the container)
CTF_COMPOSE_FILE = os.environ.get('CTF_COMPOSE_FILE', '/ctf/challenge/docker-compose.yaml')
# Host filesystem path to challenge/ — passed as --project-directory so the
# Docker daemon resolves relative bind mounts (./web/src etc.) to the right host paths
CHALLENGE_DIR    = os.environ.get('CHALLENGE_DIR', '')
PORT_RANGE_START = int(os.environ.get('PORT_RANGE_START', '8000'))
HOST_IP          = os.environ.get('HOST_IP', '127.0.0.1')
# Single secret used to derive all per-team flags
FLAG_SECRET      = os.environ.get('FLAG_SECRET', 'change-me-flag-secret')

TZ = ZoneInfo('America/New_York')


def _ts_to_ms(ts_str: str) -> int:
    """Convert a UTC SQLite timestamp string to Unix milliseconds."""
    return int(datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc).timestamp() * 1000)


def _ts_to_est(ts_str: str) -> str:
    """Convert a UTC SQLite timestamp string to an EST/EDT display string."""
    dt = datetime.fromisoformat(ts_str).replace(tzinfo=timezone.utc).astimezone(TZ)
    return dt.strftime('%Y-%m-%d %H:%M %Z')

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'manager.db')

# ---------------------------------------------------------------------------
# Flag config
# ---------------------------------------------------------------------------

FLAGS = [
    {'id': 'FLAG_INSPECTED',            'name': 'Inspect the Source',    'points': 100},
    {'id': 'FLAG_LOGIN',                'name': 'Initial Access',         'points': 100},
    {'id': 'FLAG_CREDENTIAL_HARVESTER', 'name': 'Credential Harvester',   'points': 100},
    {'id': 'FLAG_ADMIN_ACCESS',         'name': 'Admin Access',           'points': 100},
    {'id': 'FLAG_FILE_UPLOAD',          'name': 'File Upload RCE',        'points': 100},
]
MAX_SCORE = sum(f['points'] for f in FLAGS)


def _team_flag(flag_id: str, team_name: str) -> str:
    """Generate a deterministic per-team flag.
    Format: CTF{<slug>_<8-char hmac>}
    e.g.  CTF{login_3a7f9c21}
    """
    slug  = flag_id.replace('FLAG_', '').lower()
    token = hmac.new(
        FLAG_SECRET.encode(),
        f'{flag_id}:{team_name}'.encode(),
        hashlib.sha256,
    ).hexdigest()[:8]
    return f'CTF{{{slug}_{token}}}'

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS teams (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                name          TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                port          INTEGER UNIQUE NOT NULL,
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status        TEXT DEFAULT 'starting'
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                team_name    TEXT NOT NULL,
                flag_id      TEXT NOT NULL,
                captured_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(team_name, flag_id)
            )
        """)
        conn.commit()


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def get_team_by_name(name: str):
    with get_db() as db:
        row = db.execute('SELECT * FROM teams WHERE name = ?', (name,)).fetchone()
        return dict(row) if row else None


def get_all_teams():
    with get_db() as db:
        rows = db.execute('SELECT * FROM teams ORDER BY id').fetchall()
        return [dict(r) for r in rows]


def set_team_status(name: str, status: str):
    with get_db() as db:
        db.execute('UPDATE teams SET status = ? WHERE name = ?', (status, name))
        db.commit()


def next_free_port() -> int:
    with get_db() as db:
        used = {r[0] for r in db.execute('SELECT port FROM teams').fetchall()}
    port = PORT_RANGE_START
    while port in used:
        port += 1
    return port


def get_team_submissions(team_name: str) -> set:
    """Return the set of flag_ids already captured by this team."""
    with get_db() as db:
        rows = db.execute(
            'SELECT flag_id FROM submissions WHERE team_name = ?', (team_name,)
        ).fetchall()
    return {r['flag_id'] for r in rows}


def record_submission(team_name: str, flag_id: str) -> bool:
    """Insert a submission. Returns True on success, False if already captured."""
    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO submissions (team_name, flag_id) VALUES (?, ?)',
                (team_name, flag_id)
            )
            db.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def get_scoreboard() -> list:
    """Return all teams ranked by score desc, last capture asc."""
    with get_db() as db:
        team_rows = db.execute('SELECT name, status FROM teams ORDER BY name').fetchall()
        sub_rows  = db.execute(
            'SELECT team_name, flag_id, captured_at FROM submissions'
        ).fetchall()

    subs: dict = defaultdict(list)
    for s in sub_rows:
        subs[s['team_name']].append(s)

    board = []
    for t in team_rows:
        team_subs  = subs[t['name']]
        flag_ids   = {s['flag_id'] for s in team_subs}
        last_cap_utc = max((s['captured_at'] for s in team_subs), default=None)
        score        = sum(f['points'] for f in FLAGS if f['id'] in flag_ids)
        board.append({
            'name':         t['name'],
            'status':       t['status'],
            'score':        score,
            'flag_ids':     flag_ids,
            'last_capture': _ts_to_est(last_cap_utc) if last_cap_utc else None,
            '_sort_key':    last_cap_utc or '9999-99-99',
        })

    board.sort(key=lambda r: (-r['score'], r['_sort_key']))
    return board

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _compose_env(port: int, team_name: str) -> dict:
    env = {**os.environ, 'PORT': str(port)}
    for f in FLAGS:
        env[f['id']] = _team_flag(f['id'], team_name)
    return env


def _compose_cmd(team_name: str) -> list:
    """Build the base `docker compose` command with correct file + project-directory."""
    cmd = ['docker', 'compose', '-p', f'ctf_{team_name.lower()}', '-f', CTF_COMPOSE_FILE]
    if CHALLENGE_DIR:
        cmd += ['--project-directory', CHALLENGE_DIR]
    return cmd


def docker_up(team_name: str, port: int):
    """Start CTF containers for a team."""
    result = subprocess.run(
        _compose_cmd(team_name) + ['up', '-d'],
        env=_compose_env(port, team_name),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logging.error('docker_up failed for %s (port %s):\nSTDOUT: %s\nSTDERR: %s',
                      team_name, port, result.stdout, result.stderr)
    else:
        logging.info('docker_up started containers for team %s on port %s', team_name, port)


def docker_down(team_name: str, port: int):
    """Stop and wipe CTF containers + volumes for a team."""
    subprocess.run(
        _compose_cmd(team_name) + ['down', '-v'],
        env=_compose_env(port, team_name),
        check=False,
    )


def _web_container_running(team_name: str) -> bool:
    """Return True if the team's web container is in 'running' state."""
    project = f'ctf_{team_name.lower()}'
    result = subprocess.run(
        ['docker', 'ps',
         '--filter', f'name={project}-web',
         '--filter', 'status=running',
         '--format', '{{.Names}}'],
        capture_output=True, text=True, timeout=10,
    )
    return project in result.stdout


def _poll_until_ready(team_name: str, port: int, timeout: int = 180):
    """Background thread: poll via Docker socket until the web container is running."""
    deadline = time.time() + timeout
    logging.info('Polling started for team %s (timeout %ss)', team_name, timeout)
    while time.time() < deadline:
        try:
            if _web_container_running(team_name):
                time.sleep(2)
                set_team_status(team_name, 'ready')
                logging.info('Team %s is ready', team_name)
                return
        except Exception as exc:
            logging.warning('Poll check error for %s: %s', team_name, exc)
        time.sleep(5)
    logging.error('Team %s timed out waiting for web container', team_name)
    set_team_status(team_name, 'error')


def launch_and_poll(team_name: str, port: int):
    """Start containers then poll in a background thread."""
    docker_up(team_name, port)
    t = threading.Thread(target=_poll_until_ready, args=(team_name, port), daemon=True)
    t.start()

# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'team' not in session:
            flash('Please log in first.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Routes — public
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    if 'team' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    name      = request.form.get('name', '').strip()
    password  = request.form.get('password', '')
    password2 = request.form.get('password2', '')

    if not re.fullmatch(r'[a-z0-9_-]{1,32}', name):
        flash('Team name must be 1–32 chars: lowercase letters, numbers, _ or -.', 'error')
        return redirect(url_for('index'))
    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('index'))
    if password != password2:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('index'))

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    port    = next_free_port()

    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO teams (name, password_hash, port, status) VALUES (?,?,?,?)',
                (name, pw_hash, port, 'starting')
            )
            db.commit()
    except sqlite3.IntegrityError:
        flash('Team name already taken — please log in instead.', 'error')
        return redirect(url_for('index'))

    threading.Thread(target=launch_and_poll, args=(name, port), daemon=True).start()

    session['team'] = name
    flash(f'Instance for "{name}" is starting up — this takes ~30 seconds.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['POST'])
def login():
    name     = request.form.get('name', '').strip()
    password = request.form.get('password', '').encode()

    team = get_team_by_name(name)
    if not team or not bcrypt.checkpw(password, team['password_hash'].encode()):
        flash('Invalid team name or password.', 'error')
        return redirect(url_for('index'))

    session['team'] = name
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ---------------------------------------------------------------------------
# Routes — team dashboard + flag submission
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    team = get_team_by_name(session['team'])
    if not team:
        session.clear()
        return redirect(url_for('index'))
    instance_url = f'http://{HOST_IP}:{team["port"]}'
    captured     = get_team_submissions(session['team'])
    score        = sum(f['points'] for f in FLAGS if f['id'] in captured)
    return render_template('dashboard.html',
                           team=team,
                           instance_url=instance_url,
                           flags=FLAGS,
                           captured=captured,
                           score=score,
                           max_score=MAX_SCORE)


@app.route('/submit', methods=['POST'])
@login_required
def submit_flag():
    team_name = session['team']
    submitted = request.form.get('flag', '').strip()

    matched_id = None
    for f in FLAGS:
        if submitted == _team_flag(f['id'], team_name):
            matched_id = f['id']
            break

    if matched_id is None:
        flash('Incorrect flag.', 'error')
        return redirect(url_for('dashboard'))

    captured = get_team_submissions(team_name)
    if matched_id in captured:
        flash('You already captured that flag!', 'info')
        return redirect(url_for('dashboard'))

    record_submission(team_name, matched_id)
    flag_name = next(f['name'] for f in FLAGS if f['id'] == matched_id)
    flash(f'Correct! "{flag_name}" captured — +100 pts', 'success')
    return redirect(url_for('dashboard'))


@app.route('/scoreboard')
def scoreboard():
    board = get_scoreboard()

    # Build per-team cumulative score time series for the graph
    with get_db() as db:
        team_rows = db.execute('SELECT name, created_at FROM teams').fetchall()
        sub_rows  = db.execute(
            'SELECT team_name, flag_id, captured_at FROM submissions ORDER BY captured_at'
        ).fetchall()

    created = {r['name']: r['created_at'] for r in team_rows}
    subs_by_team: dict = defaultdict(list)
    for s in sub_rows:
        subs_by_team[s['team_name']].append(s)

    graph_data = {}
    for team_name, subs in subs_by_team.items():
        start_ms = _ts_to_ms(created.get(team_name) or subs[0]['captured_at'])
        series = [{'x': start_ms, 'y': 0}]
        score = 0
        for s in subs:
            pts = next((f['points'] for f in FLAGS if f['id'] == s['flag_id']), 0)
            score += pts
            series.append({'x': _ts_to_ms(s['captured_at']), 'y': score})
        graph_data[team_name] = series

    return render_template('scoreboard.html', board=board, flags=FLAGS,
                           max_score=MAX_SCORE, graph_data=graph_data)

# ---------------------------------------------------------------------------
# Routes — admin
# ---------------------------------------------------------------------------

@app.route('/admin')
def admin():
    token = request.cookies.get('admin_token') or request.args.get('token', '')
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        return render_template('admin_login.html'), 403
    teams = get_all_teams()
    for t in teams:
        captured  = get_team_submissions(t['name'])
        t['score']    = sum(f['points'] for f in FLAGS if f['id'] in captured)
        t['captures'] = len(captured)
    resp = app.make_response(render_template('admin.html', teams=teams, max_score=MAX_SCORE))
    if token:
        resp.set_cookie('admin_token', token, httponly=True, samesite='Lax')
    return resp


@app.route('/admin/stop/<team_name>', methods=['POST'])
def admin_stop(team_name):
    token = request.cookies.get('admin_token', '')
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        return 'Forbidden', 403

    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    threading.Thread(
        target=lambda: (docker_down(team_name, team['port']),
                        set_team_status(team_name, 'stopped')),
        daemon=True
    ).start()
    flash(f'Stopping "{team_name}"…', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/restart/<team_name>', methods=['POST'])
def admin_restart(team_name):
    token = request.cookies.get('admin_token', '')
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        return 'Forbidden', 403

    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    set_team_status(team_name, 'starting')
    threading.Thread(
        target=launch_and_poll, args=(team_name, team['port']), daemon=True
    ).start()
    flash(f'Restarting "{team_name}"…', 'info')
    return redirect(url_for('admin'))

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
