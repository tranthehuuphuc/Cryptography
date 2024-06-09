from flask import Flask, request, jsonify, session
from firebase_admin import credentials, firestore, initialize_app
import jwt
import datetime
import secrets
import bcrypt

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'

cred = credentials.Certificate("app/account_service.json")
initialize_app(cred)
db = firestore.client()

def generate_session_secret_key():
    return secrets.token_hex(32)

def create_jwt(payload, secret_key):
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    user_ref = db.collection('users').where('username', '==', username).where('password', '==', password).stream()
    user = next(user_ref, None)
    
    if user:
        user_data = user.to_dict()
        stored_hashed_password = user_data['password'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            session['secret_key'] = generate_session_secret_key()  # Tạo khóa bí mật mới cho phiên
            user_data = user.to_dict()
            payload = {
                'user_id': user.id,
                'role': user_data['role']
            }
            token = create_jwt(payload, session['secret_key'])  # Tạo JWT với khóa bí mật phiên mới
            session['jwt'] = token # Lưu JWT vào phiên
            return jsonify({'token': token}), 200 # Trả về JWT cho người dùng
        
    return jsonify({'message': 'Invalid credentials'}), 401

if __name__ == '__main__':
    app.run(debug=True, port=5000)