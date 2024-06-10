from flask import Flask, request, jsonify, session
from flask_cors import CORS
import jwt
import datetime

app = Flask(__name__)
CORS(app)
app.config['SESSION_TYPE'] = 'filesystem'

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
                        if server_payload['role'] == 'admin':
                            return jsonify({'message': 'Hello admin!'})
                        else:
                            return jsonify({'message': 'Hello user!'})
                    else:
                        return jsonify({'message': 'Unauthorized'}), 401
                else:
                    return jsonify({'message': 'Session expired'}), 401
            else:
                return jsonify({'message': 'Invalid token'}), 401
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    except Exception as e:
        return jsonify({'message': f'Internal server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(port=5002, debug=True)
