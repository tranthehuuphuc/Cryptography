from flask import Flask, request, jsonify, session
from firebase_admin import credentials, firestore, initialize_app
import jwt
import datetime
import secrets
import bcrypt
from flask_cors import CORS
from flask_session import Session
from redis import Redis
import logging

app = Flask(__name__)
CORS(app)

# Flask-Session configuration
app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_REDIS'] = Redis(host='127.0.0.1', port=6379, db=1)  # Ensure this matches Django's Redis config

Session(app)

cred = credentials.Certificate("credentials.json")
initialize_app(cred)
db = firestore.client()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_session_secret_key():
    return secrets.token_hex(32)

def create_jwt(payload, secret_key):
    payload['exp'] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user_ref = db.collection('users').where('username', '==', username).stream()
    user = next(user_ref, None)

    if user:
        user_data = user.to_dict()
        stored_hashed_password = user_data['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            session['secret_key'] = generate_session_secret_key()
            payload = {'user_id': user.id, 'role': user_data['role']}
            token = create_jwt(payload, session['secret_key'])
            session['jwt'] = token
            session.modified = True
            logger.info(f"Flask session after login: {dict(session)}")
            return jsonify({'token': token}), 200
        return jsonify({'message': 'Wrong password'}), 401
    return jsonify({'message': 'No user'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)
