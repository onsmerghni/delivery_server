import os
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt
import bcrypt

app = Flask(__name__)
CORS(app)

JWT_SECRET = os.environ.get('JWT_SECRET', 'pfa2026_secret_key')
DB_PATH = os.environ.get('DB_PATH', 'livraison.db')
PORT = int(os.environ.get('PORT', 8080))

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db:
        db.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT NOT NULL,
        boss_id INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS positions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        driver_id INTEGER NOT NULL,
        lat REAL,
        lon REAL,
        speed REAL,
        state TEXT,
        events INTEGER,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        driver_id INTEGER NOT NULL,
        alert_type TEXT,
        severity TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()
    print("✅ Base de données initialisée")

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                return jsonify({'error': 'Token manquant'}), 401
            token = auth[7:]
            payload = decode_token(token)
            if not payload:
                return jsonify({'error': 'Token invalide'}), 401
            if roles and payload.get('role') not in roles:
                return jsonify({'error': 'Accès refusé'}), 403
            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'livraison-pfa2026'})

@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        role = data.get('role', 'driver')
        name = data.get('name', '')
        boss_email = data.get('boss_email')

        if not email or not password or not name:
            return jsonify({'error': 'Champs manquants'}), 400

        db = get_db()
        c = db.cursor()
        
        existing = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
        if existing:
            return jsonify({'error': 'Email déjà utilisé'}), 409

        boss_id = None
        if role == 'driver' and boss_email:
            boss = c.execute('SELECT id FROM users WHERE email=? AND role=?', (boss_email, 'boss')).fetchone()
            if boss:
                boss_id = boss['id']

        c.execute('INSERT INTO users (email, password_hash, role, name, boss_id) VALUES (?, ?, ?, ?, ?)',
                  (email, hash_password(password), role, name, boss_id))
        db.commit()

        return jsonify({'success': True, 'user_id': c.lastrowid, 'role': role}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()

        if not user or not verify_password(password, user['password_hash']):
            return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

        token = create_token(user['id'], user['role'])
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'name': user['name']
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/data/position', methods=['POST'])
@require_auth(roles=['driver'])
def send_position():
    try:
        data = request.get_json()
        driver_id = request.user['user_id']
        lat = data.get('lat')
        lon = data.get('lon')
        speed = data.get('speed', 0)
        state = data.get('state', 'normal')
        events = data.get('events', 0)

        db = get_db()
        db.execute('INSERT INTO positions (driver_id, lat, lon, speed, state, events) VALUES (?, ?, ?, ?, ?, ?)',
                   (driver_id, lat, lon, speed, state, events))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/fleet/live', methods=['GET'])
@require_auth(roles=['boss'])
def fleet_live():
    try:
        boss_id = request.user['user_id']
        db = get_db()
        drivers = db.execute('''
            SELECT u.id, u.name, u.email, p.lat, p.lon, p.speed, p.state, p.timestamp
            FROM users u
            LEFT JOIN positions p ON p.id = (SELECT id FROM positions WHERE driver_id=u.id ORDER BY id DESC LIMIT 1)
            WHERE u.boss_id=? AND u.role='driver'
        ''', (boss_id,)).fetchall()
        
        result = []
        for d in drivers:
            result.append({
                'id': d['id'],
                'name': d['name'],
                'email': d['email'],
                'position': {
                    'lat': d['lat'], 'lon': d['lon'], 'speed': d['speed'], 
                    'state': d['state'], 'timestamp': d['timestamp']
                } if d['lat'] else None
            })
        return jsonify({'drivers': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    print(f"🚀 Serveur sur port {PORT}")
    app.run(host='0.0.0.0', port=PORT)