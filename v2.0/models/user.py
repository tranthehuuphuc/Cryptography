from config import db
from utils.hash_helper import hash_password

def create_user(username, password, role):
    hashed_password = hash_password(password)
    user_data = {
        'username': username,
        'password': hashed_password,
        'role': role,
        'refresh_token': ''
    }
    user_ref = db.collection('users').document(username)
    user_ref.set(user_data)
