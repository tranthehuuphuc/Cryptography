import jwt
import datetime
from flask import current_app

def create_access_token(username):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60),
        'iat': datetime.datetime.utcnow(),
        'sub': username
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def create_refresh_token(username):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=1200),
        'iat': datetime.datetime.utcnow(),
        'sub': username
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token):
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
