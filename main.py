from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

PORT = int(os.environ.get('PORT', 8080))

@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'livraison-pfa2026'})

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    return jsonify({
        'success': True,
        'message': 'Compte créé (mode test)',
        'email': data.get('email')
    })

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    return jsonify({
        'token': 'test_token_123',
        'user': {
            'id': 1,
            'email': data.get('email'),
            'role': 'boss',
            'name': 'Test User'
        }
    })

if __name__ == '__main__':
    print(f"🚀 Serveur test sur port {PORT}")
    app.run(host='0.0.0.0', port=PORT)