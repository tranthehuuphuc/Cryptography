from flask import Flask, request, make_response, render_template, redirect, url_for
from utils.jwt_helper import create_access_token, create_refresh_token, decode_token
from utils.hash_helper import hash_password, check_password
from controllers.api_controller import api_bp
from dotenv import load_dotenv
from config import db
import os

load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.register_blueprint(api_bp, url_prefix='/api')

@app.route('/', methods=['GET'])
def home():
    if request.method == 'GET':
        # Check if the user is logged in
        if not request.cookies.get('refresh_token'):
            return redirect(url_for('logout'))
        
        # Check if the access token is valid
        payload = decode_token(request.cookies.get('refresh_token'))
        if not payload:
            return redirect(url_for('logout'))
        
        # Check if the user exists
        username = payload['sub']
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if not user.exists:
            return redirect(url_for('logout'))
        
        user_data = user.to_dict()
        return render_template('home.html', role=user_data.get('role'))
    
    # If the request method is not GET, redirect to the login page
    return redirect(url_for('logout'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user exists
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if user.exists:
            # Check if the password is correct
            user_data = user.to_dict()
            if check_password(password, user_data.get('password')):
                # Create access and refresh tokens
                access_token = create_access_token(username)
                refresh_token = create_refresh_token(username)
                # Store the refresh token in the database
                store_refresh_token(username, refresh_token)

                response = make_response(redirect(url_for('home')))
                response.set_cookie('access_token', access_token, httponly=True) # httponly=True makes the cookie inaccessible from JavaScript
                response.set_cookie('refresh_token', refresh_token, httponly=True) # httponly=True makes the cookie inaccessible from JavaScript
                return response
            else:
                # If the password is incorrect, return an error message
                return render_template('login.html', error="Bad username or password")
        else:
            # If the user does not exist, return an error message
            return render_template('login.html', error="Bad username or password")

    elif request.method == 'GET':
        # Check if the user is already logged in
        refresh_token = request.cookies.get('refresh_token')
        if refresh_token:
            payload = decode_token(refresh_token)
            if payload:
                return redirect(url_for('home'))
            else:
                return redirect(url_for('logout'))
            
        # If the user is not logged in, return the login page
        return render_template('login.html')
    
    # If the request method is not GET or POST, return the login page
    return redirect(url_for('logout'))
    
def store_refresh_token(username, refresh_token):
    try:
        user_ref = db.collection('users').document(username)
        user_ref.update({'refresh_token': refresh_token})
    except Exception as e:
        print(f"An error occurred: {e}")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = hash_password(password)

        # Check if the user already exists
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if user.exists:
            return render_template('signup.html', error="User already exists")
        
        # Create a new user
        user_ref.set({
            'username': username,
            'password': hashed_password,
            'role': 'user',
            'refresh_token': ''
        })

        # Redirect to the login page
        return redirect(url_for('logout'))
    
    elif request.method == 'GET':
        return render_template('signup.html')
        
    # If the request method is not POST, redirect to the login page
    return redirect(url_for('logout'))
    

@app.route('/user', methods=['GET'])
def user():
    if request.method == 'GET':
        # Check if the user is logged in
        if not request.cookies.get('refresh_token'):
            return redirect(url_for('logout'))
        
        # Check if the access token is valid
        payload = decode_token(request.cookies.get('refresh_token'))
        if not payload:
            return redirect(url_for('logout'))
        
        # Check if the user exists
        username = payload['sub']
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if not user.exists:
            return redirect(url_for('logout'))
        
        user_data = user.to_dict()
        return render_template('user.html', role=user_data.get('role'))
    
    # If the request method is not GET, redirect to the login page
    return redirect(url_for('logout'))


@app.route('/admin', methods=['GET'])
def admin():
    if request.method == 'GET':
        # Check if the user is logged in
        if not request.cookies.get('refresh_token'):
            return redirect(url_for('logout'))
        
        # Check if the access token is valid
        payload = decode_token(request.cookies.get('refresh_token'))
        if not payload:
            return redirect(url_for('logout'))
        
        # Check if the user has admin role
        username = payload['sub']
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if not user.exists:
            return redirect(url_for('logout'))
        
        user_data = user.to_dict()
        if user_data.get('role') != 'admin':
            return redirect(url_for('logout'))
        
        # Redirect to the admin page
        return render_template('admin.html')
    
    # If the request method is not GET, redirect to the login page
    return redirect(url_for('logout'))


@app.route('/logout', methods=['GET'])
def logout():
    # Clear the access and refresh tokens
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response


if __name__ == '__main__':
    app.run(debug=True)
