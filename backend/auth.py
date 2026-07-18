import os
import secrets
import jwt
import bcrypt
import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, make_response
import requests

JWT_SECRET = os.environ.get('JWT_SECRET', 'bithome-dev-secret-change-in-production')
JWT_EXPIRY_HOURS = 72

SUPABASE_URL = os.environ.get('SUPABASE_URL', '')
SUPABASE_KEY = os.environ.get('SUPABASE_KEY', '')
SUPABASE_SERVICE_KEY = os.environ.get('SUPABASE_SERVICE_KEY', '')
BACKEND_URL = os.environ.get('BACKEND_URL', 'https://bithome-api.vercel.app')

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
                    email_verified INTEGER DEFAULT 0,
                    verification_token TEXT,
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

def _sb_create_user(email, username, pw_hash, verification_token=None):
    payload = {
        'email': email,
        'username': username,
        'password_hash': pw_hash,
        'is_pro': False,
        'email_verified': False,
    }
    if verification_token:
        payload['verification_token'] = verification_token
    res = _sb.table('users').insert(payload).execute()
    return res.data[0] if res.data else None

def _sb_update_pro(uid):
    _sb.table('users').update({'is_pro': True}).eq('id', uid).execute()

def _try_send_verification(email, token, supabase_key=None):
    """Send verification email via Supabase Auth signUp."""
    verify_url = f"{BACKEND_URL}/api/auth/verify?token={token}"
    print(f"[BitHome] Verification URL for {email}: {verify_url}")
    if not supabase_key and not SUPABASE_KEY:
        return False, verify_url
    try:
        from supabase import create_client
        anon = create_client(SUPABASE_URL, supabase_key or SUPABASE_KEY)
        rand_pw = secrets.token_urlsafe(16) + "Aa1!"
        result = anon.auth.sign_up({
            'email': email,
            'password': rand_pw,
            'options': {
                'data': {'verification_token': token},
                'redirect_to': verify_url
            }
        })
        if result.user:
            print(f"[BitHome] ✓ Auth user created, email sent to {email}")
            return True, verify_url
        else:
            print(f"[BitHome] sign_up returned no user")
            return False, verify_url
    except Exception as e:
        err = str(e)
        print(f"[BitHome] Email send exception: {err}")
        if 'already' in err.lower() or 'exists' in err.lower():
            try:
                from supabase import create_client
                anon = create_client(SUPABASE_URL, supabase_key or SUPABASE_KEY)
                anon.auth.sign_in_with_password({'email': email, 'password': 'force_resend_' + token[:8]})
                anon.auth.reset_password_for_email(email, {'redirect_to': verify_url})
                print(f"[BitHome] ✓ Password reset email sent to {email}")
                return True, verify_url
            except:
                pass
        return False, verify_url

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
    verification_token = secrets.token_urlsafe(32)

    if _use_supabase:
        existing = _sb_find_user_by_email(email)
        if existing:
            return jsonify({'error': 'Email already registered'}), 409
        user = _sb_create_user(email, username, pw_hash, verification_token)
        if not user:
            return jsonify({'error': 'Registration failed'}), 500
        _try_send_verification(email, verification_token)
        token = make_token(user['id'])
        return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'email_verified': False}}), 201
    else:
        with _get_db() as db:
            try:
                db.execute('INSERT INTO users (email, username, password_hash, verification_token) VALUES (?, ?, ?, ?)',
                           (email, username, pw_hash, verification_token))
                user = db.execute('SELECT id, email, username, is_pro FROM users WHERE email = ?', (email,)).fetchone()
                token = make_token(user['id'])
                return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'email_verified': False}}), 201
            except Exception:
                return jsonify({'error': 'Email or username already exists'}), 409

PORTAL_URL = os.environ.get('PORTAL_URL', 'https://bithome.pro')

@auth_bp.route('/verify', methods=['GET'])
def verify_email():
    token = request.args.get('token', '')
    if not token:
        return _verify_page('Missing verification token', False)

    if _use_supabase:
        res = _sb.table('users').select('*').eq('verification_token', token).execute()
        data = res.data
        if not data:
            return _verify_page('Invalid or expired token', False)
        user = data[0]
        if user.get('email_verified'):
            return _verify_page('Email already verified', True)
        _sb.table('users').update({
            'email_verified': True,
            'verification_token': None
        }).eq('id', user['id']).execute()
        return _verify_page('Email verified successfully! You can now log in.', True)
    else:
        with _get_db() as db:
            user = db.execute('SELECT * FROM users WHERE verification_token = ?', (token,)).fetchone()
            if not user:
                return _verify_page('Invalid or expired token', False)
            if user['email_verified']:
                return _verify_page('Email already verified', True)
            db.execute('UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?', (user['id'],))
            return _verify_page('Email verified successfully! You can now log in.', True)

def _verify_page(message, success):
    html = f'''<!DOCTYPE html><html lang="bg">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Email Verification - BITHOME</title>
<style>body{{background:#050508;color:#e2e2f0;font:14px/1.7 'Share Tech Mono',monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;}}
.card{{background:#0b0b12;border:1px solid #1c1c2d;border-radius:12px;padding:32px;max-width:400px;}}
.icon{{font-size:48px;margin-bottom:16px;}}
h2{{font-family:'Orbitron',sans-serif;color:{"#7fff00" if success else "#ff4466"};}}
.msg{{color:#747493;margin:16px 0;}}
a{{color:#f7931a;text-decoration:none;font-family:'Orbitron',sans-serif;font-size:12px;letter-spacing:0.08em;}}
</style></head><body>
<div class="card"><div class="icon">{"✅" if success else "❌"}</div>
<h2>{"VERIFIED" if success else "FAILED"}</h2>
<p class="msg">{message}</p>
{'<a href="' + PORTAL_URL + '">→ Go to BITHOME PORTAL</a>' if success else ''}
</div></body></html>'''
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp

@auth_bp.route('/check-verification', methods=['POST'])
def check_verification():
    """Check if email is confirmed in Supabase Auth and update our table."""
    data = request.get_json(force=True)
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'error': 'Email required'}), 400
    try:
        key = SUPABASE_SERVICE_KEY or SUPABASE_KEY
        ref = SUPABASE_URL.replace('https://', '').split('.')[0]
        headers = {'apikey': key, 'Authorization': 'Bearer ' + key}
        resp = requests.get(f'https://{ref}.supabase.co/auth/v1/admin/users?email={email}', headers=headers, timeout=10)
        if not resp.ok:
            return jsonify({'error': 'Failed to check verification', 'verified': False}), 500
        users = resp.json().get('users', [])
        if not users:
            return jsonify({'error': 'User not found in Supabase Auth', 'verified': False}), 404
        auth_user = users[0]
        confirmed = auth_user.get('email_confirmed_at') is not None
        if confirmed and _use_supabase:
            _sb.table('users').update({'email_verified': True, 'verification_token': None}).eq('email', email).execute()
            return jsonify({'verified': True, 'message': 'Email is confirmed!'})
        return jsonify({'verified': bool(confirmed), 'message': 'Email not yet confirmed. Check your inbox and click the link.'})
    except Exception as e:
        return jsonify({'error': str(e), 'verified': False}), 500

@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json(force=True)
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'error': 'Email required'}), 400

    if _use_supabase:
        user = _sb_find_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        if user.get('email_verified'):
            return jsonify({'message': 'Email already verified'})
        token = user.get('verification_token') or secrets.token_urlsafe(32)
        if not user.get('verification_token'):
            _sb.table('users').update({'verification_token': token}).eq('id', user['id']).execute()
        sent, url = _try_send_verification(email, token)
        return jsonify({'message': 'Verification email sent' if sent else 'Verification URL generated', 'url': url if not sent else None})
    else:
        with _get_db() as db:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            if user['email_verified']:
                return jsonify({'message': 'Email already verified'})
            token = user['verification_token'] if user['verification_token'] else secrets.token_urlsafe(32)
            if not user['verification_token']:
                db.execute('UPDATE users SET verification_token = ? WHERE id = ?', (token, user['id']))
            url = f"{BACKEND_URL}/api/auth/verify?token={token}"
            print(f"[BitHome] Verification URL: {url}")
            return jsonify({'message': 'Verification URL generated', 'url': url})

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
        is_verified = user.get('email_verified') is True or user.get('email_verified') is None
        return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'email_verified': bool(is_verified)}})
    else:
        with _get_db() as db:
            user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if not user or not _check_password(password, user['password_hash']):
                return jsonify({'error': 'Invalid email or password'}), 401
            token = make_token(user['id'])
            return jsonify({'token': token, 'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'email_verified': True}})

@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_me(user_id):
    if _use_supabase:
        user = _sb_find_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'email_verified': bool(user.get('email_verified', False)), 'created_at': user.get('created_at', '')}})
    else:
        with _get_db() as db:
            user = db.execute('SELECT id, email, username, is_pro, email_verified, created_at FROM users WHERE id = ?', (user_id,)).fetchone()
            if not user:
                return jsonify({'error': 'User not found'}), 404
            return jsonify({'user': {'id': user['id'], 'email': user['email'], 'username': user['username'], 'is_pro': bool(user['is_pro']), 'email_verified': bool(user['email_verified']), 'created_at': user['created_at']}})

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

@auth_bp.route('/test-email', methods=['GET'])
def test_email():
    """Test endpoint to check email sending."""
    email = request.args.get('email', '')
    if not email:
        return jsonify({'error': 'Provide ?email=xxx'}), 400
    try:
        import requests as _req
        key = SUPABASE_SERVICE_KEY or SUPABASE_KEY
        ref = SUPABASE_URL.replace('https://', '').split('.')[0]
        payload = {
            'email': email,
            'password': secrets.token_urlsafe(16) + "Aa1!",
            'email_confirm': False
        }
        headers = {
            'apikey': key,
            'Authorization': 'Bearer ' + key,
            'Content-Type': 'application/json'
        }
        resp = _req.post(f'https://{ref}.supabase.co/auth/v1/admin/users', json=payload, headers=headers, timeout=15)
        return jsonify({
            'status': resp.status_code,
            'response': resp.json() if resp.text else 'empty',
            'key_prefix': key[:10] + '...' if key else 'NONE',
            'ref': ref,
            'url': SUPABASE_URL
        })
    except Exception as e:
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

@auth_bp.route('/config', methods=['GET'])
def auth_config():
    return jsonify({
        'supabaseUrl': SUPABASE_URL,
        'version': '1.0'
    })

@auth_bp.route('/google-login', methods=['POST'])
def google_login():
    if not _use_supabase:
        return jsonify({'error': 'Google login requires Supabase'}), 400
    data = request.get_json(force=True)
    access_token = data.get('access_token', '')
    if not access_token:
        return jsonify({'error': 'Access token required'}), 400
    try:
        key = SUPABASE_SERVICE_KEY or SUPABASE_KEY
        ref = SUPABASE_URL.replace('https://', '').split('.')[0]
        headers = {'apikey': key, 'Authorization': 'Bearer ' + access_token}
        resp = requests.get(
            f'https://{ref}.supabase.co/auth/v1/user',
            headers=headers, timeout=10
        )
        if not resp.ok:
            return jsonify({'error': 'Invalid Google token'}), 401
        auth_user = resp.json()
        email = (auth_user.get('email') or '').strip().lower()
        if not email:
            return jsonify({'error': 'Email not provided by Google'}), 400
        existing = _sb_find_user_by_email(email)
        if existing:
            if not existing.get('email_verified'):
                _sb.table('users').update({'email_verified': True}).eq('id', existing['id']).execute()
            user = existing
        else:
            username_base = email.split('@')[0].replace('.', '_')[:20]
            username = username_base
            counter = 1
            while _sb.table('users').select('id').eq('username', username).execute().data:
                username = f"{username_base[:16]}_{counter}"
                counter += 1
            pw_hash = _hash_password(secrets.token_urlsafe(32))
            payload = {
                'email': email,
                'username': username,
                'password_hash': pw_hash,
                'is_pro': False,
                'email_verified': True,
            }
            res = _sb.table('users').insert(payload).execute()
            if not res.data:
                return jsonify({'error': 'Failed to create user'}), 500
            user = res.data[0]
        token = make_token(user['id'])
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'username': user['username'],
                'is_pro': bool(user['is_pro']),
                'email_verified': True
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'db': 'supabase' if _use_supabase else 'sqlite'})
