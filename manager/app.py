"""
CTF Manager — Flask web app that manages per-team Docker CTF instances.

Environment variables (set in manager/docker-compose.yaml):
  ADMIN_TOKEN       — token required to access /admin routes
  CTF_COMPOSE_FILE  — HOST path to project/docker-compose.yaml
  SECRET_KEY        — Flask session signing key
  PORT_RANGE_START  — first port to assign to teams (default 8000)
  HOST_IP           — IP / hostname shown to teams in their dashboard URL
"""

import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from contextlib import contextmanager
from functools import wraps

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
CTF_COMPOSE_FILE = os.environ.get('CTF_COMPOSE_FILE', '/ctf/challenge/docker-compose.yaml')
PORT_RANGE_START = int(os.environ.get('PORT_RANGE_START', '8000'))
HOST_IP          = os.environ.get('HOST_IP', '127.0.0.1')

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'manager.db')

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

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _compose_env(port: int) -> dict:
    return {**os.environ, 'PORT': str(port)}


def docker_up(team_name: str, port: int):
    """Start CTF containers for a team (non-blocking; status set to 'starting')."""
    result = subprocess.run(
        ['docker', 'compose', '-p', f'ctf_{team_name}',
         '-f', CTF_COMPOSE_FILE, 'up', '-d'],
        env=_compose_env(port),
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
        ['docker', 'compose', '-p', f'ctf_{team_name}',
         '-f', CTF_COMPOSE_FILE, 'down', '-v'],
        env=_compose_env(port),
        check=False,
    )


def _web_container_running(team_name: str) -> bool:
    """Return True if the team's web container is in 'running' state."""
    project = f'ctf_{team_name}'
    result = subprocess.run(
        ['docker', 'ps',
         '--filter', f'name={project}-web',
         '--filter', 'status=running',
         '--format', '{{.Names}}'],
        capture_output=True, text=True, timeout=10,
    )
    return project in result.stdout


def _poll_until_ready(team_name: str, port: int, timeout: int = 180):
    """Background thread: poll via Docker socket until the web container is running.

    Replaces the previous HTTP-based poll which failed on remote servers where
    NAT loopback is not available (manager container cannot reach HOST_IP:PORT).
    """
    deadline = time.time() + timeout
    logging.info('Polling started for team %s (timeout %ss)', team_name, timeout)
    while time.time() < deadline:
        try:
            if _web_container_running(team_name):
                # Give Apache a moment to finish binding before marking ready
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
    name     = request.form.get('name', '').strip()
    password = request.form.get('password', '')
    password2= request.form.get('password2', '')

    # Validate
    if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', name):
        flash('Team name must be 1–32 chars: letters, numbers, _ or -.', 'error')
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

    # Start containers in background
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
# Routes — team dashboard
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    team = get_team_by_name(session['team'])
    if not team:
        session.clear()
        return redirect(url_for('index'))
    instance_url = f'http://{HOST_IP}:{team["port"]}'
    return render_template('dashboard.html', team=team, instance_url=instance_url)

# ---------------------------------------------------------------------------
# Routes — admin
# ---------------------------------------------------------------------------

@app.route('/admin')
def admin():
    token = request.cookies.get('admin_token') or request.args.get('token', '')
    if not ADMIN_TOKEN or token != ADMIN_TOKEN:
        return render_template('admin_login.html'), 403
    teams = get_all_teams()
    resp = app.make_response(render_template('admin.html', teams=teams))
    # Persist the token in a cookie so subsequent POSTs carry it
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

# Ensure the DB is initialised whenever the module is loaded
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
