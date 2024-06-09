from flask import Flask, request, jsonify
import jwt
import datetime
from firebase_admin import credentials, firestore, initialize_app
from Crypto.Cipher import AES
import base64
import os

app = Flask(__name__)
cred = credentials.Certificate("./account_service.json")
initialize_app(cred)
db = firestore.client()
SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

# Khóa AES 256-bit (32 bytes)
AES_KEY = os.urandom(32)

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

def generate_token(user_id, role):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='RS256')
    encrypted_token = encrypt(token, AES_KEY)
    return encrypted_token

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user_ref = db.collection('users').where('username', '==', username).where('password', '==', password).stream()
    user = next(user_ref, None)
    if user:
        user_data = user.to_dict()
        token = generate_token(user.id, user_data['role'])
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(port=5001, ssl_context=('cert.pem', 'key.pem'))
