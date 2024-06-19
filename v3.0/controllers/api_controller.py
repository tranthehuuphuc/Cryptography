from flask import Blueprint, request, jsonify, redirect, url_for
from utils.jwt_helper import create_access_token, decode_token
from utils.abac_policy import check_user_access
from config import db
import datetime
import requests

api_bp = Blueprint('api', __name__)

@api_bp.route('/auth', methods=['GET'])
def auth():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect(url_for('login'))
    
    payload = decode_token(access_token)
    if not payload:
        return redirect(url_for('login'))
    
    resource = request.args.get('resource')
    if not resource:
        return jsonify({"msg": "No resource specified"}), 400
    
    # Check if user exists
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if not user.exists:
        return redirect(url_for('login'))
    
    # Check if user has access
    if not check_user_access(username, resource):
        return jsonify({"msg": "Access denied"}), 403
    
    # Check session
    exp = payload['exp']
    if exp < datetime.datetime.utcnow():
        # if access token is expired
        response = refresh_token(username)
        return jsonify(response.json()), response.status_code
    
    return jsonify({"msg": "Access granted"}), 200
    
def refresh_token(username):
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    refresh_token = user.to_dict().get('refresh_token')

    payload = decode_token(refresh_token)
    if payload:
        if payload['exp'] < datetime.datetime.utcnow():
            return redirect(url_for('login'))
        new_access_token = create_access_token(username)
        response = jsonify(access_token=new_access_token)
        response.set_cookie('access_token', new_access_token)
        return response
    
    return redirect(url_for('login'))

@api_bp.route('/admin-api', methods=['GET', 'POST', 'PUT'])
def admin_api():
    resource = 'admin-api'
    response = requests.get(api_bp.auth, params={'resource': resource})
    if response.status_code != 200:
        return jsonify(response.json()), response.status_code
    
    if request.method == 'GET':
        docs = db.collection('users').stream()
        data_list = [doc.to_dict() for doc in docs]
        return jsonify(data_list), 200
    
    if request.method == 'POST':
        data = request.json
        db.collection('users').add(data)
        return jsonify({"msg": "Data added successfully"}), 201
    
    if request.method == 'PUT':
        data = request.json
        doc_id = data.get('id')
        db.collection('data').document(doc_id).set(data)
        return jsonify({"msg": "Data updated successfully"}), 200

@api_bp.route('/user-api', methods=['GET'])
def user_api():
    resource = 'user-api'
    response = requests.get(api_bp.auth, params={'resource': resource})
    if response.status_code != 200:
        return jsonify(response.json()), response.status_code
    
    docs = db.collection('users').stream()
    data_list = [doc.to_dict() for doc in docs]
    return jsonify(data_list), 200

@api_bp.route('/data', methods=['GET'])
def get_data():
    token = request.cookies.get('access_token')
    if token:
        payload = decode_token(token)
        if payload:
            username = payload['sub']
            if check_user_access(username, 'read'):
                docs = db.collection('data').stream()
                data_list = [doc.to_dict() for doc in docs]
                return jsonify(data_list), 200
            return jsonify({"msg": "Access denied"}), 403
        return jsonify({"msg": "Invalid token"}), 401
    return jsonify({"msg": "Token required"}), 401



    