from flask import Blueprint, request, jsonify, redirect, url_for, render_template, make_response
from config import db
from utils.jwt_helper import create_access_token, create_refresh_token, decode_token
from utils.hash_helper import hash_password, check_password

auth_bp = Blueprint('auth', __name__)

@

@auth_bp.route('/authentication', methods=['POST'])
def authen():
    