from flask import Flask, request, jsonify
import jwt
import os
from Crypto.Cipher import AES
import base64
from functools import wraps

app = Flask(__name__)
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

# Khóa AES giống như khóa trong Authentication Service
AES_KEY = os.getenv('AES_KEY', 'default_aes_key').encode()

def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    return data[:-ord(data[len(data)-1:])]

def encrypt(data, key):
    data = pad(data)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted).decode()

def decrypt(data, key):
    encrypted = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    return unpad(decrypted).decode()

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            token = token.split(' ')[1]
            decrypted_token = decrypt(token, AES_KEY)
            data = jwt.decode(decrypted_token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(data, *args, **kwargs)
    return decorator

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(data, *args, **kwargs):
            role = data.get('role', '')
            if role not in required_roles:
                return jsonify({'message': 'Permission denied'}), 403
            return f(data, *args, **kwargs)
        return wrapper
    return decorator

@app.route('/admin', methods=['GET'])
@token_required
@role_required(['admin'])
def admin(data):
    return jsonify({'message': 'This is an admin route', 'user_id': data['user_id'], 'role': data['role']})

@app.route('/user', methods=['GET'])
@token_required
@role_required(['user', 'admin'])
def user(data):
    return jsonify({'message': 'This is a user route', 'user_id': data['user_id'], 'role': data['role']})

if __name__ == '__main__':
    app.run(port=5002, ssl_context=('cert.pem', 'key.pem'))