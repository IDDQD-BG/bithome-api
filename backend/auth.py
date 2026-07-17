import os
import jwt
import bcrypt
import datetime
from functools import wraps
from flask import Blueprint, request, jsonify

JWT_SECRET = os.environ.get('JWT_SECRET', 'bithome-dev-secret-change-in-production')
JWT_EXPIRY_HOURS = 72

SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

if SUPABASE_URL and SUPABASE_KEY:
    from supabase import create_client
    _sb = create_client(SUPABASE_URL, SUPABASE_KEY)
    _use_supabase = True
else:
    import sqlite3 as _sqlite3
    _AUTH_DB = os.path.join(os.path.dirname(__file__), 'bithome.db')
    _use_supabase = False

    def _get_db():
        conn = _sqlite3.connect(_AUTH_DB)
        conn.row_factory = _sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        return conn

    def _init_db():
        with _get_db() as db:
            db.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_pro INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            ''')
    _init_db()

def make_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return f(payload['user_id'], *args, **kwargs)
    return decorated

def _hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def _check_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

# ---- Supabase helpers ----

def _sb_find_user_by_email(email):
    res = _sb.table('users').select('*').eq('email', email).execute()
    data = res.data
    return data[0] if data else None

def _sb_find_user_by_id(uid):
    res = _sb.table('users').select('*').eq('id', uid).execute()
    data = res.data
    return data[0] if data else None

def _sb_create_user(email, username, pw_hash):
    res = _sb.table('users').insert({
        'email': email,
        'username': username,
        'password_hash': pw_hash,
        'is_pro': False
    }).execute()
    return res.data[0] if res.data else None

def _sb_update_pro(uid):
    _sb.table('users').update({'is_pro': True}).eq('id', uid).execute()

# ---- Endpoints ----

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(force=True)
    email = (data.get('email') or '').strip().lower()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not email or '@' not in email:
        return jsonify({'error': 'Valid email required'}), 400
    if not username or len(username) < 2:
        return jsonify({'error': 'Username must be at least 2 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    pw_hash = _hash_password(password)

    if _use_supabase:
        existing = _sb_find_user_by_email(email)
        if existing:
            return jsonify({'error': 'Email already registered'}), 409
        user = _sb_create_user(email, username, pw_hash)
        if not user:
            return jsonify({'error': 'Registration failed'}), 500
        token = make_token(user['id'])
        return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro'])}}), 201
    else:
        with _get_db() as db:
            try:
                db.execute('INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)',
                           (email, username, pw_hash))
                user = db.execute('SELECT id, email, username, is_pro FROM users WHERE email = ?', (email,)).fetchone()
                token = make_token(user['id'])
                return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro'])}}), 201
            except Exception:
                return jsonify({'error': 'Email or username already exists'}), 409

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(force=True)
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    if _use_supabase:
        user = _sb_find_user_by_email(email)
        if not user or not _check_password(password, user['password_hash']):
            return jsonify({'error': 'Invalid email or password'}), 401
        token = make_token(user['id'])
        return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro'])}})
    else:
        with _get_db() as db:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if not user or not _check_password(password, user['password_hash']):
                return jsonify({'error': 'Invalid email or password'}), 401
            token = make_token(user['id'])
            return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro'])}})

@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_me(user_id):
    if _use_supabase:
        user = _sb_find_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'created_at': user.get('created_at', '')}})
    else:
        with _get_db() as db:
            user = db.execute('SELECT id, email, username, is_pro, created_at FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            return jsonify({'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'created_at': user['created_at']}})

@auth_bp.route('/upgrade', methods=['POST'])
@require_auth
def upgrade_pro(user_id):
    data = request.get_json(force=True)
    access_key = data.get('access_key', '').strip()
    if not access_key or len(access_key) < 8:
        return jsonify({'error': 'Invalid access key'}), 400

    if _use_supabase:
        _sb_update_pro(user_id)
    else:
        with _get_db() as db:
            db.execute('UPDATE users SET is_pro = 1 WHERE id = ?', (user_id,))

    return jsonify({'message': 'PRO access activated', 'is_pro': True})

@auth_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'db': 'supabase' if _use_supabase else 'sqlite'})
