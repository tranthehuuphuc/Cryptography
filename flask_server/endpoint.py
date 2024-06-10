from flask import Flask, request, jsonify, session
from firebase_admin import credentials, firestore, initialize_app
import jwt
import datetime
import secrets
import logging
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.secret_key = secrets.token_hex(32)
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize Firebase
cred = credentials.Certificate("credentials.json")
initialize_app(cred)
db = firestore.client()

# Setup logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/app_endpoint', methods=['GET'])
def app_endpoint():
    try:
        # Get client token from request headers
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'message': 'Unauthorized'}), 401
        
        client_token = auth_header.split()[1]

        # Check if session contains secret_key and jwt
        if 'secret_key' in session and 'jwt' in session:
            secret_key = session['secret_key']
            server_token = session['jwt']
            server_payload = jwt.decode(server_token, secret_key, algorithms=['HS256'])
            
            # Compare client token with server token
            if client_token == server_token:
                client_payload = jwt.decode(client_token, secret_key, algorithms=['HS256'])
                
                # Session module
                if client_payload['exp'] > datetime.datetime.utcnow().timestamp():
                    # Authentication module
                    if client_payload['user_id'] == server_payload['user_id']:
                        # Authorization module
                        if server_payload['role'] == client_payload['role']:
                            return jsonify(client_payload['role']), 200
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
        return jsonify({'message': f'Internal server error: {str(e)}'}), 500
    # auth_header = request.headers.get('Authorization')
    # if not auth_header:
    #     return jsonify({'message': 'Unauthorized'}), 401

    # secret_key = session.get('secret_key')
    # server_token = session.get('jwt')

    # if not secret_key or not server_token:
    #     return jsonify({'message': 'Unauthorized'}), 401

    # try:
    #     server_payload = jwt.decode(server_token, secret_key, algorithms=['HS256'])
    #     if server_payload['exp'] > datetime.datetime.utcnow().timestamp():
    #         if server_payload['role'] == 'admin':
    #             users = [doc.to_dict() for doc in db.collection('users').stream()]
    #             return jsonify({'users': users}), 200
    #         else:
    #             return jsonify({'message': 'Forbidden'}), 403
    #     else:
    #         return jsonify({'message': 'Session expired'}), 401
    # except jwt.ExpiredSignatureError:
    #     return jsonify({'message': 'Session expired'}), 401
    # except jwt.InvalidTokenError:
    #     return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(port=5002, debug=True)
