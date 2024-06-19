from flask import Blueprint, request, jsonify, redirect, url_for, make_response
from utils.jwt_helper import create_access_token, decode_token
from utils.abac_policy import check_user_access
from utils.hash_helper import hash_password
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
    
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if not user.exists:
        return redirect(url_for('login'))
    
    if not check_user_access(username, resource):
        return jsonify({"msg": "Access denied"}), 403
    
    exp = datetime.datetime.utcfromtimestamp(payload['exp'])
    if exp < datetime.datetime.utcnow():
        response, status_code = refresh_token(username)
        if status_code != 200:
            return response
        new_access_token = response.json.get('access_token')
        response = make_response(jsonify({"msg": "Access granted"}), 200)
        response.set_cookie('access_token', new_access_token)
        return response
    
    return jsonify({"msg": "Access granted"}), 200
    
def refresh_token(username):
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    refresh_token = user.to_dict().get('refresh_token')

    payload = decode_token(refresh_token)
    if payload:
        exp = datetime.datetime.utcfromtimestamp(payload['exp'])
        if exp < datetime.datetime.utcnow():
            return redirect(url_for('login')), 401
        new_access_token = create_access_token(username)
        response = jsonify(access_token=new_access_token)
        response.set_cookie('access_token', new_access_token)
        print("Access token refreshed")
        return response, 200
    
    return redirect(url_for('login')), 401

@api_bp.route('/admin-api', methods=['GET', 'POST', 'PUT'])
def admin_api():
    resource = 'admin-api'
    auth_url = url_for('api.auth', _external=True)
    try:
        response = requests.get(auth_url, params={'resource': resource}, cookies=request.cookies)
    except requests.RequestException as e:
        return jsonify({"msg": f"Error connecting to auth service: {str(e)}"}), 500

    if response.status_code != 200:
        return jsonify(response.json()), response.status_code
    
    if request.method == 'GET':
        docs = db.collection('users').stream()
        data_list = [doc.to_dict() for doc in docs]
        return jsonify(data_list), 200
    
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        hashed_password = hash_password(password)
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if user.exists:
            return jsonify({"msg": "Username already exists"}), 400
        
        user_ref.set({
            'username': username,
            'password': hashed_password,
            'role': role,
            'refresh_token': ''
        })
        return jsonify({"msg": "Data added successfully"}), 201
    
    if request.method == 'PUT':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if not user.exists:
            return jsonify({"msg": "Username not found"}), 404
        
        update_data = {'role': role}
        if password:
            hashed_password = hash_password(password)
            update_data['password'] = hashed_password
        user_ref.update(update_data)
        return jsonify({"msg": "Data updated successfully"}), 200


@api_bp.route('/user-api', methods=['GET'])
def user_api():
    resource = 'user-api'
    auth_url = url_for('api.auth', _external=True)
    try:
        response = requests.get(auth_url, params={'resource': resource}, cookies=request.cookies)
    except requests.RequestException as e:
        return jsonify({"msg": f"Error connecting to auth service: {str(e)}"}), 500

    if response.status_code != 200:
        return jsonify(response.json()), response.status_code
    
    if request.method == 'GET':
        docs = db.collection('users').stream()
        data_list = [doc.to_dict() for doc in docs]
        return jsonify(data_list), 200
