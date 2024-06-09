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

