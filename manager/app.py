"""
CTF Manager — Flask web app that manages per-team Docker CTF instances.

Environment variables (set in manager/docker-compose.yaml):
  ADMIN_TOKEN       — token required to access /admin routes
  CTF_COMPOSE_FILE  — compose file path inside the manager container
  CHALLENGE_DIR     — absolute host path to challenge/ (for --project-directory)
  SECRET_KEY        — Flask session signing key
  PORT_RANGE_START  — first port to assign to teams (default 8000)
  HOST_IP           — IP / hostname shown to teams in their dashboard URL
  FLAG_INSPECTED, FLAG_LOGIN, FLAG_SQL_INJECTION,
  FLAG_USER_ESCALATION, FLAG_FILE_UPLOAD — correct flag values for submission scoring
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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s [%(levelname)s] %(message)s')

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'change-me-in-production')

csrf    = CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app,
                  storage_uri="memory://", default_limits=[])

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
    # Points reflect difficulty (75–200). fb_multiplier applied to first capture only.
    {'id': 'FLAG_INSPECTED',            'name': 'Inspect the Source',   'points':  75, 'fb_multiplier': 1.2},
    {'id': 'FLAG_LOGIN',                'name': 'Initial Access',        'points': 100, 'fb_multiplier': 1.2},
    {'id': 'FLAG_SQL_INJECTION', 'name': 'SQL Injection',         'points': 150, 'fb_multiplier': 1.2},
    {'id': 'FLAG_USER_ESCALATION',         'name': 'User Escalation',       'points': 125, 'fb_multiplier': 1.2},
    {'id': 'FLAG_FILE_UPLOAD',          'name': 'File Upload RCE',       'points': 200, 'fb_multiplier': 1.2},
]
# Base total (no first blood bonuses). MAX_POSSIBLE includes all first blood bonuses.
MAX_SCORE    = sum(f['points'] for f in FLAGS)
MAX_POSSIBLE = sum(int(f['points'] * f['fb_multiplier']) for f in FLAGS)

# Cost to reveal a flag's challenge name on the dashboard
FLAG_NAME_COST = 5

# Hints — sequential per flag (order N requires order N-1 purchased first).
# cost is deducted from the team's score when purchased.
HINTS = [
    # ── FLAG_INSPECTED ──────────────────────────────────────────────────────
    {'id':  1, 'flag_id': 'FLAG_INSPECTED',            'order': 1, 'cost': 10,
     'text': "Something is hidden in plain sight on one of the public pages."},
    {'id':  2, 'flag_id': 'FLAG_INSPECTED',            'order': 2, 'cost': 25,
     'text': "View the HTML source of the Products page (Ctrl+U)."},
    # ── FLAG_LOGIN ──────────────────────────────────────────────────────────
    {'id':  3, 'flag_id': 'FLAG_LOGIN',                'order': 1, 'cost': 15,
     'text': "Web servers often tell crawlers which paths to avoid. Have you checked?"},
    {'id':  4, 'flag_id': 'FLAG_LOGIN',                'order': 2, 'cost': 30,
     'text': "Check /robots.txt — then follow the disallowed path."},
    {'id':  5, 'flag_id': 'FLAG_LOGIN',                'order': 3, 'cost': 50,
     'text': "The staff resources directory contains an onboarding document with default credentials."},
    # ── FLAG_SQL_INJECTION (SQL Injection) ───────────────────────────
    {'id':  6, 'flag_id': 'FLAG_SQL_INJECTION', 'order': 1, 'cost': 20,
     'text': "After login, one page lets you search for staff. Does it sanitise input?"},
    {'id':  7, 'flag_id': 'FLAG_SQL_INJECTION', 'order': 2, 'cost': 45,
     'text': "The lookup page builds a SQL LIKE query directly from the search field — no sanitisation."},
    {'id':  8, 'flag_id': 'FLAG_SQL_INJECTION', 'order': 3, 'cost': 70,
     'text': "Try a UNION SELECT to dump the users table: ' UNION SELECT username,password,3,4,5 FROM users-- -"},
    # ── FLAG_USER_ESCALATION (User Escalation) ────────────────────────────────
    {'id':  9, 'flag_id': 'FLAG_USER_ESCALATION',         'order': 1, 'cost': 20,
     'text': "The users table contains credentials for other accounts, not just employees."},
    {'id': 10, 'flag_id': 'FLAG_USER_ESCALATION',         'order': 2, 'cost': 45,
     'text': "The password column is unsalted MD5. Crack it with rockyou.txt."},
    # ── FLAG_FILE_UPLOAD ────────────────────────────────────────────────────
    {'id': 11, 'flag_id': 'FLAG_FILE_UPLOAD',          'order': 1, 'cost': 25,
     'text': "The admin panel has a file management section. Does it validate what you upload?"},
    {'id': 12, 'flag_id': 'FLAG_FILE_UPLOAD',          'order': 2, 'cost': 55,
     'text': "The upload feature accepts any file type. A PHP script will execute on the server."},
    {'id': 13, 'flag_id': 'FLAG_FILE_UPLOAD',          'order': 3, 'cost': 80,
     'text': "Uploaded files are served from /uploads/. A PHP webshell with ?cmd=cat+/flag.txt will read the flag."},
]


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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS hint_purchases (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                team_name    TEXT NOT NULL,
                hint_id      INTEGER NOT NULL,
                purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(team_name, hint_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS name_purchases (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                team_name    TEXT NOT NULL,
                flag_id      TEXT NOT NULL,
                purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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


def get_capture_order() -> dict:
    """Return {flag_id: [team_name, ...]} ordered by capture time (earliest first)."""
    with get_db() as db:
        rows = db.execute(
            'SELECT flag_id, team_name FROM submissions ORDER BY captured_at, id'
        ).fetchall()
    order: dict = defaultdict(list)
    for r in rows:
        order[r['flag_id']].append(r['team_name'])
    return dict(order)


def get_revealed_names(team_name: str) -> set:
    """Return the set of flag IDs whose names have been purchased by this team."""
    with get_db() as db:
        rows = db.execute(
            'SELECT flag_id FROM name_purchases WHERE team_name = ?', (team_name,)
        ).fetchall()
    return {r['flag_id'] for r in rows}


def get_all_name_reveal_costs() -> dict:
    """Return {team_name: total_name_reveal_cost} for all teams (single query)."""
    with get_db() as db:
        rows = db.execute(
            'SELECT team_name, COUNT(*) as cnt FROM name_purchases GROUP BY team_name'
        ).fetchall()
    return {r['team_name']: r['cnt'] * FLAG_NAME_COST for r in rows}


def get_purchased_hints(team_name: str) -> set:
    """Return the set of hint IDs already purchased by this team."""
    with get_db() as db:
        rows = db.execute(
            'SELECT hint_id FROM hint_purchases WHERE team_name = ?', (team_name,)
        ).fetchall()
    return {r['hint_id'] for r in rows}


def get_hint_cost(team_name: str) -> int:
    """Total points deducted for hints purchased by this team."""
    purchased = get_purchased_hints(team_name)
    return sum(h['cost'] for h in HINTS if h['id'] in purchased)


def get_all_hint_costs() -> dict:
    """Return {team_name: total_hint_cost} for all teams (single query)."""
    with get_db() as db:
        rows = db.execute('SELECT team_name, hint_id FROM hint_purchases').fetchall()
    costs: dict = defaultdict(int)
    hint_map = {h['id']: h['cost'] for h in HINTS}
    for r in rows:
        costs[r['team_name']] += hint_map.get(r['hint_id'], 0)
    return dict(costs)


def _flag_points(base: int, fb_mult: float, position: int) -> int:
    """Points for capturing a flag at a given position (1-indexed).
    1st  : first blood  — base * fb_mult
    2nd–3rd: full base points
    4th+ : base − (position − 3), floor 1
    """
    if position == 1:
        return int(base * fb_mult)
    if position <= 3:
        return base
    return max(1, base - (position - 3))


def _calc_score(team_name: str, flag_ids: set, capture_order: dict, hint_cost: int = 0) -> int:
    """Sum positional points for captured flags, subtract hint and name-reveal costs.
    Score can go negative if deductions exceed points earned."""
    score = 0
    for f in FLAGS:
        if f['id'] in flag_ids:
            order    = capture_order.get(f['id'], [])
            position = order.index(team_name) + 1 if team_name in order else len(order) + 1
            score   += _flag_points(f['points'], f['fb_multiplier'], position)
    return score - hint_cost


def get_scoreboard() -> list:
    """Return all teams ranked by score desc, last capture asc."""
    capture_order = get_capture_order()
    hint_costs    = get_all_hint_costs()
    name_costs    = get_all_name_reveal_costs()
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
        team_subs    = subs[t['name']]
        flag_ids     = {s['flag_id'] for s in team_subs}
        last_cap_utc = max((s['captured_at'] for s in team_subs), default=None)
        hcost        = hint_costs.get(t['name'], 0) + name_costs.get(t['name'], 0)
        score        = _calc_score(t['name'], flag_ids, capture_order, hcost)
        # Position per flag (1-indexed)
        flag_positions = {
            fid: capture_order[fid].index(t['name']) + 1
            for fid in flag_ids
            if t['name'] in capture_order.get(fid, [])
        }
        board.append({
            'name':         t['name'],
            'status':       t['status'],
            'score':        score,
            'flag_ids':      flag_ids,
            'flag_positions': flag_positions,
            'last_capture':  _ts_to_est(last_cap_utc) if last_cap_utc else None,
            '_sort_key':     last_cap_utc or '9999-99-99',
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


# Serialize docker compose up calls — concurrent MySQL inits can deadlock health checks
_compose_lock = threading.Lock()


def docker_up(team_name: str, port: int):
    """Start CTF containers for a team (serialized to prevent concurrent init races)."""
    with _compose_lock:
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


def _web_container_state(team_name: str) -> str:
    """Return the Docker state of the web container: 'running', 'created', 'exited', or ''."""
    project = f'ctf_{team_name.lower()}'
    result = subprocess.run(
        ['docker', 'ps', '-a',
         '--filter', f'name={project}-web',
         '--format', '{{.State}}'],
        capture_output=True, text=True, timeout=10,
    )
    output = result.stdout.strip().lower()
    if 'running' in output:
        return 'running'
    if 'created' in output:
        return 'created'
    if 'exited' in output:
        return 'exited'
    return ''


def _poll_until_ready(team_name: str, port: int, timeout: int = 180):
    """Background thread: poll via Docker socket until the web container is running.

    If the web container is stuck in 'created' state (db health check raced with
    a concurrent compose up), we start it explicitly rather than waiting for compose.
    """
    project  = f'ctf_{team_name.lower()}'
    deadline = time.time() + timeout
    logging.info('Polling started for team %s (timeout %ss)', team_name, timeout)
    while time.time() < deadline:
        try:
            state = _web_container_state(team_name)
            if state == 'running':
                time.sleep(2)
                set_team_status(team_name, 'ready')
                logging.info('Team %s is ready', team_name)
                return
            elif state == 'created':
                # Compose left the container in Created — db health check wasn't
                # done when compose exited. Start the container directly.
                logging.info('Web container for %s is Created; starting it now', team_name)
                subprocess.run(
                    ['docker', 'start', f'{project}-web-1'],
                    capture_output=True, timeout=15,
                )
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


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login_page'))
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
@limiter.limit("5 per hour")
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
@limiter.limit("20 per minute")
def login():
    name     = request.form.get('name', '').strip()
    password = request.form.get('password', '').encode()

    team = get_team_by_name(name)
    if not team or not bcrypt.checkpw(password, team['password_hash'].encode()):
        flash('Invalid team name or password.', 'error')
        return redirect(url_for('index'))

    session['team'] = name
    return redirect(url_for('dashboard'))


@app.route('/logout', methods=['POST'])
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
    capture_order  = get_capture_order()
    captured       = get_team_submissions(session['team'])
    hcost          = get_hint_cost(session['team'])
    name_cost      = len(get_revealed_names(session['team'])) * FLAG_NAME_COST
    total_deduct   = hcost + name_cost
    score          = _calc_score(session['team'], captured, capture_order, total_deduct)
    revealed_names = get_revealed_names(session['team'])
    # Per-flag position and points earned
    flag_pos = {}
    flag_pts = {}
    for f in FLAGS:
        if f['id'] in captured:
            order = capture_order.get(f['id'], [])
            pos   = order.index(session['team']) + 1 if session['team'] in order else len(order) + 1
            flag_pos[f['id']] = pos
            flag_pts[f['id']] = _flag_points(f['points'], f['fb_multiplier'], pos)
    instance_url = f'http://{HOST_IP}:{team["port"]}'
    return render_template('dashboard.html',
                           team=team,
                           instance_url=instance_url,
                           flags=FLAGS,
                           captured=captured,
                           flag_pos=flag_pos,
                           flag_pts=flag_pts,
                           revealed_names=revealed_names,
                           flag_name_cost=FLAG_NAME_COST,
                           score=score,
                           hint_cost=total_deduct,
                           max_score=MAX_SCORE)


@app.route('/submit', methods=['POST'])
@login_required
def submit_flag():
    team_name = session['team']
    submitted = request.form.get('flag', '').strip()

    matched_flag = None
    for f in FLAGS:
        if submitted == _team_flag(f['id'], team_name):
            matched_flag = f
            break

    if matched_flag is None:
        flash('Incorrect flag.', 'error')
        return redirect(url_for('dashboard'))

    captured = get_team_submissions(team_name)
    if matched_flag['id'] in captured:
        flash('You already captured that flag!', 'info')
        return redirect(url_for('dashboard'))

    record_submission(team_name, matched_flag['id'])
    capture_order = get_capture_order()
    order    = capture_order.get(matched_flag['id'], [])
    position = order.index(team_name) + 1 if team_name in order else len(order) + 1
    pts      = _flag_points(matched_flag['points'], matched_flag['fb_multiplier'], position)

    if position == 1:
        flash(f'FIRST BLOOD! "{matched_flag["name"]}" — +{pts} pts '
              f'({matched_flag["points"]} × {matched_flag["fb_multiplier"]})', 'success')
    else:
        flash(f'Correct! "{matched_flag["name"]}" captured — +{pts} pts (#{position})', 'success')
    return redirect(url_for('dashboard'))


@app.route('/hints')
@login_required
def hints():
    team_name = session['team']
    if not get_team_by_name(team_name):
        session.clear()
        flash('Team not found. Please log in again.', 'error')
        return redirect(url_for('index'))
    purchased = get_purchased_hints(team_name)
    total_cost = sum(h['cost'] for h in HINTS if h['id'] in purchased)

    # Build per-flag hint lists, gating later hints behind earlier purchases
    flag_hints: dict = {}
    for flag in FLAGS:
        fid = flag['id']
        ordered = sorted([h for h in HINTS if h['flag_id'] == fid], key=lambda h: h['order'])
        visible = []
        for h in ordered:
            # Always show hint 1; show hint N only if hint N-1 is purchased
            if h['order'] == 1 or any(
                prev['id'] in purchased
                for prev in ordered if prev['order'] == h['order'] - 1
            ):
                visible.append(h)
        flag_hints[fid] = visible

    revealed_names = get_revealed_names(team_name)
    return render_template('hints.html',
                           flags=FLAGS,
                           flag_hints=flag_hints,
                           purchased=purchased,
                           total_cost=total_cost,
                           revealed_names=revealed_names)


@app.route('/hints/buy', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def buy_hint():
    team_name = session['team']
    if not get_team_by_name(team_name):
        session.clear()
        flash('Team not found. Please log in again.', 'error')
        return redirect(url_for('index'))
    try:
        hint_id = int(request.form.get('hint_id', 0))
    except (ValueError, TypeError):
        flash('Invalid hint.', 'error')
        return redirect(url_for('hints'))

    hint = next((h for h in HINTS if h['id'] == hint_id), None)
    if not hint:
        flash('Invalid hint.', 'error')
        return redirect(url_for('hints'))

    # Enforce sequential unlock: must own previous hint first
    if hint['order'] > 1:
        ordered = sorted(
            [h for h in HINTS if h['flag_id'] == hint['flag_id']],
            key=lambda h: h['order']
        )
        prev = next((h for h in ordered if h['order'] == hint['order'] - 1), None)
        if prev:
            purchased = get_purchased_hints(team_name)
            if prev['id'] not in purchased:
                flash('Unlock the previous hint first.', 'error')
                return redirect(url_for('hints'))

    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO hint_purchases (team_name, hint_id) VALUES (?, ?)',
                (team_name, hint_id)
            )
            db.commit()
        flash(f'Hint unlocked — -{hint["cost"]} pts applied to your score.', 'info')
    except sqlite3.IntegrityError:
        flash('Already purchased.', 'info')
    return redirect(url_for('hints'))


@app.route('/reveal-name', methods=['POST'])
@login_required
@limiter.limit("20 per minute")
def reveal_name():
    team_name = session['team']
    if not get_team_by_name(team_name):
        session.clear()
        flash('Team not found. Please log in again.', 'error')
        return redirect(url_for('index'))
    flag_id = request.form.get('flag_id', '').strip()
    if not any(f['id'] == flag_id for f in FLAGS):
        flash('Invalid flag.', 'error')
        return redirect(url_for('dashboard'))
    try:
        with get_db() as db:
            db.execute(
                'INSERT INTO name_purchases (team_name, flag_id) VALUES (?, ?)',
                (team_name, flag_id)
            )
            db.commit()
        flash(f'Challenge name revealed — -{FLAG_NAME_COST} pts applied.', 'info')
    except sqlite3.IntegrityError:
        flash('Already revealed.', 'info')
    return redirect(url_for('dashboard'))


@app.route('/scoreboard')
def scoreboard():
    board = get_scoreboard()

    # Build per-team cumulative score time series for the graph.
    # Merge flag captures, hint purchases, and name reveals into a single
    # timeline so the score drops at the moment a purchase is made.
    with get_db() as db:
        team_rows  = db.execute('SELECT name, created_at FROM teams').fetchall()
        sub_rows   = db.execute(
            'SELECT team_name, flag_id, captured_at FROM submissions'
        ).fetchall()
        hint_rows  = db.execute(
            'SELECT team_name, hint_id, purchased_at FROM hint_purchases'
        ).fetchall()
        name_rows  = db.execute(
            'SELECT team_name, flag_id AS fid, purchased_at FROM name_purchases'
        ).fetchall()

    created      = {r['name']: r['created_at'] for r in team_rows}
    hint_cost_map = {h['id']: h['cost'] for h in HINTS}

    # Build per-team event lists: (timestamp_str, kind, payload)
    # kind='flag' payload=flag_id  kind='deduct' payload=pts_cost
    events_by_team: dict = defaultdict(list)
    for s in sub_rows:
        events_by_team[s['team_name']].append((s['captured_at'], 'flag', s['flag_id']))
    for h in hint_rows:
        cost = hint_cost_map.get(h['hint_id'], 0)
        events_by_team[h['team_name']].append((h['purchased_at'], 'deduct', cost))
    for n in name_rows:
        events_by_team[n['team_name']].append((n['purchased_at'], 'deduct', FLAG_NAME_COST))

    capture_order = get_capture_order()
    graph_data = {}
    for team_name, events in events_by_team.items():
        events.sort(key=lambda e: e[0])
        start_ts = created.get(team_name) or events[0][0]
        series = [{'x': _ts_to_ms(start_ts), 'y': 0}]
        running_ids: set = set()
        running_deduct = 0
        for ts, kind, payload in events:
            if kind == 'flag':
                running_ids.add(payload)
            else:
                running_deduct += payload
            score = _calc_score(team_name, running_ids, capture_order, running_deduct)
            series.append({'x': _ts_to_ms(ts), 'y': score})
        graph_data[team_name] = series

    # Actual min/max across all data points — Y-axis scales to fit whatever teams score
    all_y = [pt['y'] for series in graph_data.values() for pt in series]
    graph_max = max(all_y, default=100)
    graph_min = min(all_y, default=0)

    return render_template('scoreboard.html', board=board, flags=FLAGS,
                           max_score=MAX_SCORE, max_possible=MAX_POSSIBLE,
                           graph_data=graph_data, graph_max=graph_max, graph_min=graph_min)

# ---------------------------------------------------------------------------
# Routes — admin
# ---------------------------------------------------------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_page():
    if session.get('is_admin'):
        return redirect(url_for('admin'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == 'admin' and ADMIN_TOKEN and hmac.compare_digest(password, ADMIN_TOKEN):
            session['is_admin'] = True
            return redirect(url_for('admin'))
        flash('Invalid username or password.', 'error')
    return render_template('admin_login.html')


@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.pop('is_admin', None)
    return redirect(url_for('admin_login_page'))


@app.route('/admin')
@admin_required
def admin():
    teams         = get_all_teams()
    capture_order = get_capture_order()
    hint_costs    = get_all_hint_costs()
    name_costs    = get_all_name_reveal_costs()
    for t in teams:
        captured      = get_team_submissions(t['name'])
        hcost         = hint_costs.get(t['name'], 0) + name_costs.get(t['name'], 0)
        t['score']    = _calc_score(t['name'], captured, capture_order, hcost)
        t['captures'] = len(captured)
    return render_template('admin.html', teams=teams, max_score=MAX_SCORE)


@app.route('/admin/stop/<team_name>', methods=['POST'])
@admin_required
def admin_stop(team_name):
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
@admin_required
def admin_restart(team_name):
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


@app.route('/admin/reset-password/<team_name>', methods=['POST'])
@admin_required
def admin_reset_password(team_name):
    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    new_password = request.form.get('new_password', '')
    if len(new_password) < 8:
        flash('New password must be at least 8 characters.', 'error')
        return redirect(url_for('admin'))

    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    with get_db() as db:
        db.execute('UPDATE teams SET password_hash = ? WHERE name = ?', (pw_hash, team_name))
        db.commit()

    flash(f'Password reset for "{team_name}".', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/delete/<team_name>', methods=['POST'])
@admin_required
def admin_delete(team_name):
    team = get_team_by_name(team_name)
    if not team:
        flash(f'Team "{team_name}" not found.', 'error')
        return redirect(url_for('admin'))

    # Best-effort Docker cleanup (may already be gone if remove_team.sh was used)
    threading.Thread(
        target=lambda: docker_down(team_name, team['port']),
        daemon=True
    ).start()

    with get_db() as db:
        db.execute('DELETE FROM submissions WHERE team_name = ?', (team_name,))
        db.execute('DELETE FROM teams WHERE name = ?', (team_name,))
        db.commit()

    flash(f'Team "{team_name}" deleted.', 'info')
    return redirect(url_for('admin'))

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
