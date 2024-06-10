from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api_gateway', methods=['GET'])
def api_gateway():
    # Get client token from request headers
    client_token = request.headers.get('Authorization')
    data = request.json
    api_id = data.get('api_id')

    # Forward client token to app_endpoint
    if client_token and api_id:
        payload = {'api_id': api_id}
        response = requests.get('http://localhost:5002/app_endpoint', headers={'Authorization': client_token}, json=payload)
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        elif response.status_code == 403:
            return jsonify(response.json()), 403
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    return jsonify({'message': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(port=5001, debug=True)