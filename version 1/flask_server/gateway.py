from flask import Flask, request, jsonify, session
import requests
from flask_session import Session
from redis import Redis
import logging

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

@app.route('/api_gateway', methods=['GET'])
def api_gateway():
    logger.info(f"Session before API call: {dict(session)}")
    client_token = request.headers.get('Authorization')

    if client_token:
        response = requests.get('http://localhost:5002/app_endpoint', headers={'Authorization': client_token})
        
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    return jsonify({'message': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(port=5001, debug=True)
