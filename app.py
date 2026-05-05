from flask import Flask, request, jsonify, session, render_template, send_from_directory
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import re
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True)

DB_PATH = os.path.join(os.path.dirname(__file__), 'database.db')

# ─── DATABASE SETUP ────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS admins (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT    NOT NULL,
            email     TEXT    NOT NULL UNIQUE,
            password  TEXT    NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS reset_tokens (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id   INTEGER NOT NULL,
            token      TEXT    NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            used       INTEGER DEFAULT 0,
            FOREIGN KEY (admin_id) REFERENCES admins(id)
        );

        CREATE TABLE IF NOT EXISTS opportunities (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id            INTEGER NOT NULL,
            name                TEXT    NOT NULL,
            duration            TEXT    NOT NULL,
            start_date          TEXT    NOT NULL,
            description         TEXT    NOT NULL,
            skills              TEXT    NOT NULL,
            category            TEXT    NOT NULL,
            future_opportunities TEXT   NOT NULL,
            max_applicants      INTEGER,
            created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admins(id)
        );
    ''')
    conn.commit()
    conn.close()

init_db()

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def is_valid_email(email):
    return re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email) is not None

def current_admin_id():
    return session.get('admin_id')

# ─── ROUTES: SERVE FRONTEND ───────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('admin.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

# ─── AUTH: SIGNUP ─────────────────────────────────────────────────────────────

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    full_name        = (data.get('full_name') or '').strip()
    email            = (data.get('email') or '').strip().lower()
    password         = data.get('password') or ''
    confirm_password = data.get('confirm_password') or ''

    # Validate
    if not full_name:
        return jsonify({'error': 'Full name is required'}), 400
    if not email or not is_valid_email(email):
        return jsonify({'error': 'A valid email address is required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO admins (full_name, email, password) VALUES (?, ?, ?)',
            (full_name, email, hash_password(password))
        )
        conn.commit()
        return jsonify({'message': 'Account created successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'An account with this email already exists'}), 409
    finally:
        conn.close()

# ─── AUTH: LOGIN ──────────────────────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def login():
    data        = request.get_json()
    email       = (data.get('email') or '').strip().lower()
    password    = data.get('password') or ''
    remember_me = data.get('remember_me', False)

    if not email or not password:
        return jsonify({'error': 'Invalid email or password'}), 401

    conn = get_db()
    admin = conn.execute(
        'SELECT * FROM admins WHERE email = ? AND password = ?',
        (email, hash_password(password))
    ).fetchone()
    conn.close()

    if not admin:
        return jsonify({'error': 'Invalid email or password'}), 401

    session.permanent = bool(remember_me)
    if remember_me:
        app.permanent_session_lifetime = timedelta(days=30)
    else:
        app.permanent_session_lifetime = timedelta(hours=0)   # ends on browser close

    session['admin_id']    = admin['id']
    session['admin_email'] = admin['email']
    session['admin_name']  = admin['full_name']

    return jsonify({
        'message':    'Login successful',
        'email':      admin['email'],
        'full_name':  admin['full_name'],
    })

# ─── AUTH: LOGOUT ─────────────────────────────────────────────────────────────

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'})

# ─── AUTH: FORGOT PASSWORD ────────────────────────────────────────────────────

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data  = request.get_json()
    email = (data.get('email') or '').strip().lower()

    if not email or not is_valid_email(email):
        # Always return the same message to protect privacy
        return jsonify({'message': 'If this email is registered, a reset link has been sent.'})

    conn = get_db()
    admin = conn.execute('SELECT * FROM admins WHERE email = ?', (email,)).fetchone()

    if admin:
        token      = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)
        conn.execute(
            'INSERT INTO reset_tokens (admin_id, token, expires_at) VALUES (?, ?, ?)',
            (admin['id'], token, expires_at.strftime('%Y-%m-%d %H:%M:%S'))
        )
        conn.commit()
        reset_link = f"http://localhost:5000/api/reset-password/{token}"
        # Log internally instead of emailing
        app.logger.info(f"[PASSWORD RESET] Email: {email} | Link: {reset_link} | Expires: {expires_at}")

    conn.close()
    return jsonify({'message': 'If this email is registered, a reset link has been sent.'})

# ─── AUTH: RESET PASSWORD ─────────────────────────────────────────────────────

@app.route('/api/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data         = request.get_json()
    new_password = data.get('password') or ''

    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    conn  = get_db()
    row   = conn.execute(
        "SELECT * FROM reset_tokens WHERE token = ? AND used = 0",
        (token,)
    ).fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Invalid or already-used reset link'}), 400

    expires_at = datetime.strptime(row['expires_at'], '%Y-%m-%d %H:%M:%S')
    if datetime.utcnow() > expires_at:
        conn.close()
        return jsonify({'error': 'This reset link has expired. Please request a new one.'}), 400

    conn.execute('UPDATE admins SET password = ? WHERE id = ?',
                 (hash_password(new_password), row['admin_id']))
    conn.execute('UPDATE reset_tokens SET used = 1 WHERE id = ?', (row['id'],))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Password reset successfully'})

# ─── AUTH: SESSION CHECK ──────────────────────────────────────────────────────

@app.route('/api/me', methods=['GET'])
def me():
    if not current_admin_id():
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({
        'admin_id':  session['admin_id'],
        'email':     session['admin_email'],
        'full_name': session['admin_name'],
    })

# ─── OPPORTUNITIES: LIST ──────────────────────────────────────────────────────

@app.route('/api/opportunities', methods=['GET'])
def list_opportunities():
    admin_id = current_admin_id()
    if not admin_id:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM opportunities WHERE admin_id = ? ORDER BY created_at DESC',
        (admin_id,)
    ).fetchall()
    conn.close()

    return jsonify([_opp_to_dict(r) for r in rows])

# ─── OPPORTUNITIES: CREATE ────────────────────────────────────────────────────

@app.route('/api/opportunities', methods=['POST'])
def create_opportunity():
    admin_id = current_admin_id()
    if not admin_id:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.get_json()
    name                 = (data.get('name') or '').strip()
    duration             = (data.get('duration') or '').strip()
    start_date           = (data.get('start_date') or '').strip()
    description          = (data.get('description') or '').strip()
    skills               = (data.get('skills') or '').strip()
    category             = (data.get('category') or '').strip()
    future_opportunities = (data.get('future_opportunities') or '').strip()
    max_applicants       = data.get('max_applicants')

    # Validate required fields
    if not all([name, duration, start_date, description, skills, category, future_opportunities]):
        return jsonify({'error': 'All required fields must be filled'}), 400

    valid_categories = ['technology', 'business', 'design', 'marketing', 'data', 'other']
    if category not in valid_categories:
        return jsonify({'error': 'Invalid category'}), 400

    if max_applicants is not None and max_applicants != '':
        try:
            max_applicants = int(max_applicants)
        except (ValueError, TypeError):
            return jsonify({'error': 'Max applicants must be a number'}), 400
    else:
        max_applicants = None

    conn = get_db()
    cursor = conn.execute(
        '''INSERT INTO opportunities
           (admin_id, name, duration, start_date, description, skills,
            category, future_opportunities, max_applicants)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (admin_id, name, duration, start_date, description, skills,
         category, future_opportunities, max_applicants)
    )
    conn.commit()
    new_id = cursor.lastrowid
    row = conn.execute('SELECT * FROM opportunities WHERE id = ?', (new_id,)).fetchone()
    conn.close()

    return jsonify(_opp_to_dict(row)), 201

# ─── OPPORTUNITIES: GET ONE ───────────────────────────────────────────────────

@app.route('/api/opportunities/<int:opp_id>', methods=['GET'])
def get_opportunity(opp_id):
    admin_id = current_admin_id()
    if not admin_id:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db()
    row  = conn.execute(
        'SELECT * FROM opportunities WHERE id = ? AND admin_id = ?',
        (opp_id, admin_id)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Opportunity not found'}), 404
    return jsonify(_opp_to_dict(row))

# ─── OPPORTUNITIES: UPDATE ────────────────────────────────────────────────────

@app.route('/api/opportunities/<int:opp_id>', methods=['PUT'])
def update_opportunity(opp_id):
    admin_id = current_admin_id()
    if not admin_id:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db()
    existing = conn.execute(
        'SELECT * FROM opportunities WHERE id = ? AND admin_id = ?',
        (opp_id, admin_id)
    ).fetchone()

    if not existing:
        conn.close()
        return jsonify({'error': 'Opportunity not found'}), 404

    data = request.get_json()
    name                 = (data.get('name') or '').strip()
    duration             = (data.get('duration') or '').strip()
    start_date           = (data.get('start_date') or '').strip()
    description          = (data.get('description') or '').strip()
    skills               = (data.get('skills') or '').strip()
    category             = (data.get('category') or '').strip()
    future_opportunities = (data.get('future_opportunities') or '').strip()
    max_applicants       = data.get('max_applicants')

    if not all([name, duration, start_date, description, skills, category, future_opportunities]):
        conn.close()
        return jsonify({'error': 'All required fields must be filled'}), 400

    if max_applicants is not None and max_applicants != '':
        try:
            max_applicants = int(max_applicants)
        except (ValueError, TypeError):
            conn.close()
            return jsonify({'error': 'Max applicants must be a number'}), 400
    else:
        max_applicants = None

    conn.execute(
        '''UPDATE opportunities SET
           name=?, duration=?, start_date=?, description=?, skills=?,
           category=?, future_opportunities=?, max_applicants=?
           WHERE id=? AND admin_id=?''',
        (name, duration, start_date, description, skills,
         category, future_opportunities, max_applicants, opp_id, admin_id)
    )
    conn.commit()
    row = conn.execute('SELECT * FROM opportunities WHERE id = ?', (opp_id,)).fetchone()
    conn.close()

    return jsonify(_opp_to_dict(row))

# ─── OPPORTUNITIES: DELETE ────────────────────────────────────────────────────

@app.route('/api/opportunities/<int:opp_id>', methods=['DELETE'])
def delete_opportunity(opp_id):
    admin_id = current_admin_id()
    if not admin_id:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db()
    existing = conn.execute(
        'SELECT * FROM opportunities WHERE id = ? AND admin_id = ?',
        (opp_id, admin_id)
    ).fetchone()

    if not existing:
        conn.close()
        return jsonify({'error': 'Opportunity not found'}), 404

    conn.execute('DELETE FROM opportunities WHERE id = ? AND admin_id = ?', (opp_id, admin_id))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Opportunity deleted successfully'})

# ─── HELPER ───────────────────────────────────────────────────────────────────

def _opp_to_dict(row):
    return {
        'id':                   row['id'],
        'admin_id':             row['admin_id'],
        'name':                 row['name'],
        'duration':             row['duration'],
        'start_date':           row['start_date'],
        'description':          row['description'],
        'skills':               row['skills'],
        'category':             row['category'],
        'future_opportunities': row['future_opportunities'],
        'max_applicants':       row['max_applicants'],
        'created_at':           row['created_at'],
    }

# ──────────────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, port=5000)