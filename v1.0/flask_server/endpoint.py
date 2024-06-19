from flask import Flask, request, jsonify, session
from firebase_admin import credentials, firestore, initialize_app
import jwt
import datetime
import logging
from flask_cors import CORS
from flask_session import Session
from redis import Redis

app = Flask(__name__)
CORS(app)

app.secret_key = 'your_secret_key'
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'session:'
app.config['SESSION_REDIS'] = Redis(host='127.0.0.1', port=6379, db=1)
app.config['SESSION_COOKIE_NAME'] = 'sessionid'
app.config['SESSION_COOKIE_DOMAIN'] = 'localhost'
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

Session(app)

cred = credentials.Certificate("credentials.json")
initialize_app(cred)
db = firestore.client()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/app_endpoint', methods=['GET'])
def app_endpoint():
    try:
        logger.info(f"Flask session before endpoint call: {dict(session)}")
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Unauthorized'}), 401
        
        client_token = auth_header.split()[1]

        if 'secret_key' in session and 'jwt' in session:
            secret_key = session['secret_key']
            server_token = session['jwt']
            server_payload = jwt.decode(server_token, secret_key, algorithms=['HS256'])
            
            if client_token == server_token:
                client_payload = jwt.decode(client_token, secret_key, algorithms=['HS256'])
                
                if client_payload['exp'] > datetime.datetime.utcnow().timestamp():
                    if client_payload['user_id'] == server_payload['user_id']:
                        if server_payload['role'] == client_payload['role']:
                            return jsonify({'role': client_payload['role']}), 200
                        else:
                            return jsonify({'message': 'Unauthorized'}), 401
                    else:
                        return jsonify({'message': 'Unauthenticated'}), 401
                else:
                    return jsonify({'message': 'Session expired'}), 401
            else:
                return jsonify({'message': 'Invalid token'}), 401
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    except Exception as e:
        logger.error(f"Internal server error: {str(e)}")
        return jsonify({'message': f'Internal server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(port=5002, debug=True)
