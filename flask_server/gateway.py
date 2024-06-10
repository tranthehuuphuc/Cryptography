from flask import Flask, request, jsonify, session
import requests
import jwt

app = Flask(__name__)

@app.route('/api_gateway', methods=['GET'])
def api_gateway():
    # Get client token from request headers
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'Unauthorized'}, status=401)

    token = token.split(' ')[1]  # Bỏ từ "Bearer"
    
    try:
        secret_key = session.get('secret_key')
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return jsonify({'role': payload['role']}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    except KeyError:
        return jsonify({'message': 'Secret key missing in session'}), 600
    except Exception as e:
        return jsonify({'message': f'Internal server error: {str(e)}'}), 500

    # Forward client token to app_endpoint
    if client_token:
        response = requests.get('http://localhost:5002/app_endpoint', headers={'Authorization': client_token})
        
        if response.status_code == 200:
            return jsonify(response.json()), 200
        elif response.status_code == 403:
            return jsonify(response.json()), 403
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    return jsonify({'message': 'Unauthorized'}), 401

if __name__ == '__main__':
    app.run(port=5001, debug=True)