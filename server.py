"""
Serveur Flask pour projet PFA 2026
Supervision de véhicules de livraison

Endpoints :
  POST /auth/register    -> Créer compte
  POST /auth/login       -> Obtenir JWT token
  POST /data/position    -> Livreur envoie position
  POST /data/alert       -> Livreur envoie alerte
  GET  /fleet/live       -> Boss récupère positions
  GET  /fleet/history/<id> -> Historique livreur
  GET  /fleet/stats      -> Statistiques globales
  WS   /ws/fleet         -> WebSocket temps réel boss

Déploiement Railway :
  1. Créer dépôt GitHub avec server.py + requirements.txt
  2. Railway -> Deploy from GitHub
  3. Variables : JWT_SECRET, DB_PATH, PORT
"""

import os
import sqlite3
import json
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_sock import Sock
import jwt
import bcrypt

# ═══════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════

app = Flask(__name__)
CORS(app)
sock = Sock(app)

JWT_SECRET = os.environ.get('JWT_SECRET', 'change_me_in_production_pfa2026')
DB_PATH    = os.environ.get('DB_PATH', 'livraison.db')
PORT       = int(os.environ.get('PORT', 8000))

# Clients WebSocket connectés (boss)
ws_clients = set()

# ═══════════════════════════════════════════════════
# BASE DE DONNÉES
# ═══════════════════════════════════════════════════

def get_db():
    """Récupère la connexion SQLite (une par requête)."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initialise les tables si elles n'existent pas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('boss', 'driver')),
        name TEXT NOT NULL,
        boss_id INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (boss_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS positions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        driver_id INTEGER NOT NULL,
        lat REAL,
        lon REAL,
        speed REAL,
        state TEXT,
        events INTEGER DEFAULT 0,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (driver_id) REFERENCES users(id)
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        driver_id INTEGER NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT,
        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (driver_id) REFERENCES users(id)
    )''')

    conn.commit()
    conn.close()
    print("✅ Base de données initialisée")

# ═══════════════════════════════════════════════════
# AUTHENTIFICATION
# ═══════════════════════════════════════════════════

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
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(roles=None):
    """Décorateur pour endpoints protégés."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                return jsonify({'error': 'Token manquant'}), 401
            token = auth[7:]
            payload = decode_token(token)
            if not payload:
                return jsonify({'error': 'Token invalide ou expiré'}), 401
            if roles and payload.get('role') not in roles:
                return jsonify({'error': 'Accès refusé'}), 403
            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ═══════════════════════════════════════════════════
# ENDPOINTS : AUTHENTIFICATION
# ═══════════════════════════════════════════════════

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'livraison-pfa2026'})

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role = data.get('role', 'driver')
    name = data.get('name', '')
    boss_email = data.get('boss_email')

    if not email or not password or not name:
        return jsonify({'error': 'Champs manquants'}), 400

    if role not in ['boss', 'driver']:
        return jsonify({'error': 'Rôle invalide'}), 400

    db = get_db()
    c = db.cursor()

    # Vérifier unicité email
    existing = c.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
    if existing:
        return jsonify({'error': 'Email déjà utilisé'}), 409

    # Si livreur, trouver le boss
    boss_id = None
    if role == 'driver' and boss_email:
        boss = c.execute('SELECT id FROM users WHERE email=? AND role=?',
                         (boss_email, 'boss')).fetchone()
        if boss:
            boss_id = boss['id']

    # Créer l'utilisateur
    c.execute('''INSERT INTO users (email, password_hash, role, name, boss_id)
                 VALUES (?, ?, ?, ?, ?)''',
              (email, hash_password(password), role, name, boss_id))
    db.commit()

    return jsonify({
        'success': True,
        'user_id': c.lastrowid,
        'role': role
    }), 201

@app.route('/auth/login', methods=['POST'])
def login():
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

# ═══════════════════════════════════════════════════
# ENDPOINTS : DONNÉES (LIVREUR)
# ═══════════════════════════════════════════════════

@app.route('/data/position', methods=['POST'])
@require_auth(roles=['driver'])
def send_position():
    data = request.get_json()
    driver_id = request.user['user_id']

    lat   = data.get('lat')
    lon   = data.get('lon')
    speed = data.get('speed', 0)
    state = data.get('state', 'normal')
    events = data.get('events', 0)

    if lat is None or lon is None:
        return jsonify({'error': 'Coordonnées manquantes'}), 400

    db = get_db()
    db.execute('''INSERT INTO positions (driver_id, lat, lon, speed, state, events)
                  VALUES (?, ?, ?, ?, ?, ?)''',
               (driver_id, lat, lon, speed, state, events))
    db.commit()

    # Broadcast aux WebSockets boss
    user = db.execute('SELECT name, boss_id FROM users WHERE id=?', (driver_id,)).fetchone()
    broadcast_to_boss(user['boss_id'], {
        'type': 'position_update',
        'driver_id': driver_id,
        'driver_name': user['name'],
        'data': {
            'lat': lat, 'lon': lon, 'speed': speed,
            'state': state, 'events': events,
            'timestamp': datetime.utcnow().isoformat()
        }
    })

    return jsonify({'success': True})

@app.route('/data/alert', methods=['POST'])
@require_auth(roles=['driver'])
def send_alert():
    data = request.get_json()
    driver_id = request.user['user_id']
    alert_type = data.get('type', 'unknown')
    severity = data.get('severity', 'info')

    db = get_db()
    db.execute('''INSERT INTO alerts (driver_id, alert_type, severity)
                  VALUES (?, ?, ?)''',
               (driver_id, alert_type, severity))
    db.commit()

    # Broadcast au boss
    user = db.execute('SELECT name, boss_id FROM users WHERE id=?', (driver_id,)).fetchone()
    broadcast_to_boss(user['boss_id'], {
        'type': 'alert',
        'driver_id': driver_id,
        'driver_name': user['name'],
        'alert_type': alert_type,
        'severity': severity,
        'timestamp': datetime.utcnow().isoformat()
    })

    return jsonify({'success': True})

# ═══════════════════════════════════════════════════
# ENDPOINTS : DASHBOARD (BOSS)
# ═══════════════════════════════════════════════════

@app.route('/fleet/live', methods=['GET'])
@require_auth(roles=['boss'])
def fleet_live():
    boss_id = request.user['user_id']
    db = get_db()

    # Récupérer tous les livreurs de ce boss + leur dernière position
    drivers = db.execute('''
        SELECT u.id, u.name, u.email,
               p.lat, p.lon, p.speed, p.state, p.events, p.timestamp
        FROM users u
        LEFT JOIN positions p ON p.id = (
            SELECT id FROM positions WHERE driver_id=u.id ORDER BY id DESC LIMIT 1
        )
        WHERE u.boss_id=? AND u.role='driver'
    ''', (boss_id,)).fetchall()

    result = []
    for d in drivers:
        result.append({
            'id': d['id'],
            'name': d['name'],
            'email': d['email'],
            'position': {
                'lat': d['lat'],
                'lon': d['lon'],
                'speed': d['speed'],
                'state': d['state'],
                'events': d['events'],
                'timestamp': d['timestamp']
            } if d['lat'] is not None else None
        })

    return jsonify({'drivers': result, 'count': len(result)})

@app.route('/fleet/history/<int:driver_id>', methods=['GET'])
@require_auth(roles=['boss'])
def fleet_history(driver_id):
    boss_id = request.user['user_id']
    db = get_db()

    # Vérifier que ce livreur est à ce boss
    driver = db.execute('SELECT id FROM users WHERE id=? AND boss_id=?',
                        (driver_id, boss_id)).fetchone()
    if not driver:
        return jsonify({'error': 'Livreur non trouvé'}), 404

    # Récupérer les 500 dernières positions
    positions = db.execute('''
        SELECT lat, lon, speed, state, events, timestamp
        FROM positions
        WHERE driver_id=?
        ORDER BY id DESC
        LIMIT 500
    ''', (driver_id,)).fetchall()

    return jsonify({
        'driver_id': driver_id,
        'positions': [dict(p) for p in positions]
    })

@app.route('/fleet/stats', methods=['GET'])
@require_auth(roles=['boss'])
def fleet_stats():
    boss_id = request.user['user_id']
    db = get_db()

    # Nombre de livreurs
    total_drivers = db.execute('''
        SELECT COUNT(*) as n FROM users WHERE boss_id=? AND role='driver'
    ''', (boss_id,)).fetchone()['n']

    # Alertes aujourd'hui
    today_alerts = db.execute('''
        SELECT COUNT(*) as n FROM alerts a
        JOIN users u ON u.id = a.driver_id
        WHERE u.boss_id=? AND DATE(a.timestamp) = DATE('now')
    ''', (boss_id,)).fetchone()['n']

    # Positions enregistrées aujourd'hui
    today_positions = db.execute('''
        SELECT COUNT(*) as n FROM positions p
        JOIN users u ON u.id = p.driver_id
        WHERE u.boss_id=? AND DATE(p.timestamp) = DATE('now')
    ''', (boss_id,)).fetchone()['n']

    return jsonify({
        'total_drivers': total_drivers,
        'today_alerts': today_alerts,
        'today_positions': today_positions
    })

# ═══════════════════════════════════════════════════
# WEBSOCKET : TEMPS RÉEL POUR BOSS
# ═══════════════════════════════════════════════════

@sock.route('/ws/fleet')
def ws_fleet(ws):
    """WebSocket endpoint pour le boss."""
    # Récupérer token depuis query string
    token = request.args.get('token', '')
    payload = decode_token(token)

    if not payload or payload.get('role') != 'boss':
        ws.send(json.dumps({'error': 'Non autorisé'}))
        return

    boss_id = payload['user_id']
    client = {'ws': ws, 'boss_id': boss_id}
    ws_clients.add(client['ws'])

    try:
        ws.send(json.dumps({'type': 'connected'}))
        while True:
            msg = ws.receive()
            if msg is None:
                break
            # Les clients peuvent envoyer des ping
            if msg == 'ping':
                ws.send('pong')
    finally:
        ws_clients.discard(client['ws'])

def broadcast_to_boss(boss_id, message):
    """Envoie un message à tous les WebSockets du boss."""
    dead_clients = set()
    for ws in ws_clients:
        try:
            ws.send(json.dumps(message))
        except Exception:
            dead_clients.add(ws)
    for ws in dead_clients:
        ws_clients.discard(ws)

# ═══════════════════════════════════════════════════
# DÉMARRAGE
# ═══════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    print(f"🚀 Serveur démarré sur port {PORT}")
    print(f"📊 Base de données : {DB_PATH}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
