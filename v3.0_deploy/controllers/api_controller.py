from flask import Blueprint, request, jsonify, make_response, redirect, url_for
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
    refresh_token = request.cookies.get('refresh_token')

    # If no access token is found, try to refresh the access token
    if not access_token:
        return refresh_access_token(refresh_token)

    # Check if the access token is valid
    payload = decode_token(access_token)
    if not payload:
        return refresh_access_token(refresh_token)

    # Check if the user exists
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if not user.exists:
        return jsonify({"msg": "User not found"}), 404

    # Check if the user has access to the resource
    resource = request.args.get('resource')
    if not resource:
        return jsonify({"msg": "No resource specified"}), 400
    
    if not check_user_access(username, resource):
        return jsonify({"msg": "Access denied"}), 403

    # Check if the access token is expired
    exp = datetime.datetime.utcfromtimestamp(payload['exp'])
    if exp < datetime.datetime.utcnow():
        # If the access token is expired, try to refresh it
        return refresh_access_token(refresh_token)

    # Successfully authenticated and authorized
    return jsonify({"msg": "Access granted"}), 200

def refresh_access_token(refresh_token):
    # Check if a refresh token is found
    if not refresh_token:
        return jsonify({"msg": "No refresh token found"}), 401

    # Check if the refresh token is valid
    payload = decode_token(refresh_token)
    if not payload:
        return jsonify({"msg": "Invalid refresh token, please log in again"}), 403

    # Check if the user exists
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if not user.exists:
        return jsonify({"msg": "User not found"}), 404

    # Check if the refresh token is the same as the stored refresh token
    stored_refresh_token = user.to_dict().get('refresh_token', '')
    if refresh_token.encode('utf-8') != stored_refresh_token.encode('utf-8'):
        return jsonify({"msg": "Invalid refresh token, please log in again"}), 403
    
    # Check if the refresh token is expired
    exp = datetime.datetime.utcfromtimestamp(payload['exp'])
    if exp < datetime.datetime.utcnow():
        return jsonify({"msg": "Refresh token expired, please log in again"}), 403

    # Create a new access token
    new_access_token = create_access_token(username)
    return jsonify({'new_access_token': new_access_token}), 201


@api_bp.route('/admin-api', methods=['GET', 'POST', 'PUT', 'DELETE'])
def admin_api():
    # Check if the user is logged in
    if not request.cookies.get('access_token'):
        return redirect(url_for('logout'))
    
    resource = 'admin-api'
    auth_url = url_for('api.auth', _external=True)
        
    # Authentication and Authorization
    try:
        response = requests.get(auth_url, params={'resource': resource}, cookies=request.cookies)
    except requests.RequestException as e:
        return jsonify({"msg": f"Error connecting to auth service: {str(e)}"}), 500

    # If the user does not have access to the resource, return an error
    new_access_token = response.json().get('new_access_token')
    if response.status_code == 201:
        print("Access Token has refreshed and make new request!!!\n")

        # Set the new access token in the response
        response = make_response(jsonify({"msg": "Access Token has refreshed and make new request!!!"}), 201)
        response.set_cookie('access_token', new_access_token, httponly=True)
        return response, 201
    
    elif response.status_code != 200:
        print(f"{response.json()}\n")

        # If the response status code is not 200, redirect to the login page
        return jsonify({"msg": "Permission denied!"}), 403
    
    print("Access Token and Refresh Token are valid.\n")

    if request.method == 'GET':
        docs = db.collection('users').stream()
        data_list = []
        for doc in docs:
            user_data = doc.to_dict()
            # Remove sensitive data
            user_data.pop('password', None)
            user_data.pop('refresh_token', None)
            data_list.append(user_data)
        return jsonify(data_list), 200

    elif request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        hashed_password = hash_password(password)

        # Check if the user already exists
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if user.exists:
            return jsonify({"msg": "Username already exists"}), 400

        # Create a new user
        user_ref.set({
            'username': username,
            'password': hashed_password,
            'role': role,
            'refresh_token': ''
        })
        return jsonify({"msg": "New User added successfully"}), 200

    elif request.method == 'PUT':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        
        # Check if the user exists
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if not user.exists:
            return jsonify({"msg": "Username not found"}), 404

        update_data = {'role': role}
        if password:
            hashed_password = hash_password(password)
            update_data['password'] = hashed_password

        # Update user data
        user_ref.update(update_data)
        return jsonify({"msg": "Data updated successfully"}), 200
    
    elif request.method == 'DELETE':
        data = request.json
        username = data.get('username')

        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if not user.exists:
            return jsonify({"msg": "Username not found"}), 404

        user_ref.delete()
        return jsonify({"msg": "User deleted successfully"}), 200

    return jsonify({"msg": "Method not allowed"}), 405


@api_bp.route('/user-api', methods=['GET'])
def user_api():
    # Check if the user is logged in
    if not request.cookies.get('access_token'):
        return redirect(url_for('logout'))
    
    resource = 'user-api'
    auth_url = url_for('api.auth', _external=True)

    # Authentication and Authorization
    try:
        response = requests.get(auth_url, params={'resource': resource}, cookies=request.cookies)
    except requests.RequestException as e:
        return jsonify({"msg": f"Error connecting to auth service: {str(e)}"}), 500

    # If the user does not have access to the resource, return an error
    new_access_token = response.json().get('new_access_token')
    if response.status_code == 201:
        print("Access Token has refreshed and make new request!!!\n")

        # Set the new access token in the response
        response = make_response(jsonify({"msg": "Access Token has refreshed and make new request!!!"}), 201)
        response.set_cookie('access_token', new_access_token, httponly=True)
        return response, 201
    
    elif response.status_code != 200:
        print("Refresh Token has expired!!!\n")

        # If the response status code is not 200, redirect to the login page
        return jsonify({"msg": "Permission denied!"}), response.status_code
    
    print("Access Token and Refresh Token are valid.\n")

    if request.method == 'GET':
        docs = db.collection('users').stream()
        data_list = []
        for doc in docs:
            user_data = doc.to_dict()
            # Remove sensitive data
            user_data.pop('password', None)
            user_data.pop('refresh_token', None)
            data_list.append(user_data)
        return jsonify(data_list), 200
    
    return jsonify({"msg": "Method not allowed"}), 405