from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

AUTH_SERVICE_URL = 'https://localhost:5001'
AUTHZ_SERVICE_URL = 'https://localhost:5002'
SESSION_SERVICE_URL = 'https://localhost:5003'

@app.route('/login', methods=['POST'])
def login():
    response = requests.post(f'{AUTH_SERVICE_URL}/login', json=request.json, verify=False)
    return jsonify(response.json()), response.status_code

@app.route('/admin', methods=['GET'])
def admin():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    # Validate session
    session_response = requests.post(f'{SESSION_SERVICE_URL}/validate_session', json={'token': token}, verify=False)
    if session_response.status_code != 200:
        return jsonify(session_response.json()), session_response.status_code

    # Authorize request
    authz_response = requests.get(f'{AUTHZ_SERVICE_URL}/admin', headers={'Authorization': token}, verify=False)
    return jsonify(authz_response.json()), authz_response.status_code

@app.route('/user', methods=['GET'])
def user():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Token is missing'}), 401

    # Validate session
    session_response = requests.post(f'{SESSION_SERVICE_URL}/validate_session', json={'token': token}, verify=False)
    if session_response.status_code != 200:
        return jsonify(session_response.json()), session_response.status_code

    # Authorize request
    authz_response = requests.get(f'{AUTHZ_SERVICE_URL}/user', headers={'Authorization': token}, verify=False)
    return jsonify(authz_response.json()), authz_response.status_code

if __name__ == '__main__':
    app.run(port=5000, ssl_context=('cert.pem', 'key.pem'))
