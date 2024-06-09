from flask import Flask, request, jsonify
import jwt
import os
from Crypto.Cipher import AES
import base64

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

@app.route('/validate_session', methods=['POST'])
def validate_session():
    token = request.json.get('token')
    try:
        decrypted_token = decrypt(token, AES_KEY)
        data = jwt.decode(decrypted_token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({'status': 'valid', 'user_id': data['user_id'], 'role': data['role']})
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

if __name__ == '__main__':
    app.run(port=5003, ssl_context=('cert.pem', 'key.pem'))
