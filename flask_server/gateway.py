from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/api_gateway', methods=['GET'])
def api_gateway():
    client_token = request.headers.get('Authorization')

    if client_token:
        response = requests.get('http://localhost:5002/app_endpoint', headers={'Authorization': client_token})
        return jsonify(response.json()), response.status_code
    return jsonify({'message': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(port=5001, debug=True)
