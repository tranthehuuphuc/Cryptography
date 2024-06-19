# from flask import Blueprint, request, jsonify, redirect, url_for, render_template, make_response
# from config import db
# from utils.jwt_helper import create_access_token, create_refresh_token, decode_token
# from utils.hash_helper import hash_password, check_password

# auth_bp = Blueprint('auth', __name__)



# @auth_bp.route('/token', methods=['POST'])
# def refresh_token():
#     refresh_token = request.cookies.get('refresh_token')
#     payload = decode_token(refresh_token)
#     if payload:
#         username = payload['sub']
#         user_ref = db.collection('users').document(username)
#         user = user_ref.get()
#         if user.exists and user.to_dict().get('refresh_token') == refresh_token:
#             new_access_token = create_access_token(username)
#             response = jsonify(access_token=new_access_token)
#             response.set_cookie('access_token', new_access_token)
#             return response
#         return jsonify({"msg": "Invalid refresh token"}), 401
#     return jsonify({"msg": "Invalid refresh token"}), 401

# @auth_bp.route('/users', methods=['GET', 'POST', 'PUT'])
# def manage_users():
#     token = request.cookies.get('access_token')
#     payload = decode_token(token)
#     if not payload:
#         return jsonify({"msg": "Invalid token"}), 401
    
#     username = payload['sub']
#     user_ref = db.collection('users').document(username)
#     user = user_ref.get()
#     if not user.exists or user.to_dict().get('role') != 'admin':
#         return jsonify({"msg": "Access denied"}), 403

#     if request.method == 'GET':
#         users = db.collection('users').stream()
#         user_list = [{u.id: u.to_dict()} for u in users]
#         return jsonify(user_list), 200
    
#     if request.method == 'POST':
#         new_username = request.form.get('username')
#         new_password = request.form.get('password')
#         new_role = request.form.get('role')
#         new_user_ref = db.collection('users').document(new_username)
#         if not new_user_ref.get().exists:
#             new_user_ref.set({
#                 'password': hash_password(new_password),
#                 'role': new_role
#             })
#             return jsonify({"msg": "User added successfully"}), 201
#         return jsonify({"msg": "User already exists"}), 400
    
#     if request.method == 'PUT':
#         edit_username = request.form.get('username')
#         new_role = request.form.get('role')
#         edit_user_ref = db.collection('users').document(edit_username)
#         if edit_user_ref.get().exists:
#             edit_user_ref.update({
#                 'role': new_role
#             })
#             return jsonify({"msg": "User role updated successfully"}), 200
#         return jsonify({"msg": "User not found"}), 404
