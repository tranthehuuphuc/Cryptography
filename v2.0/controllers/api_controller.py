from flask import Blueprint, request, jsonify
from utils.jwt_helper import decode_token
from utils.abac_policy import check_user_access
from config import db

api_bp = Blueprint('api', __name__)

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
