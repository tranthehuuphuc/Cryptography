from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api_gateway', methods=['GET'])
def api_gateway():
    # Get client token from request headers
    client_token = request.headers.get('Authorization')

    # Forward client token to app_endpoint
    if client_token:
        response = requests.get('http://localhost:5000/app_endpoint', headers={'Authorization': client_token})
        return response.json()
    return jsonify({'message': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(port=5001, debug=True)