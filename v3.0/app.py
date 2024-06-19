from flask import Flask, render_template, redirect, url_for, request, make_response
from utils.jwt_helper import create_access_token, create_refresh_token, decode_token
from utils.hash_helper import hash_password, check_password
from controllers.api_controller import api_bp
from config import db

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.register_blueprint(api_bp, url_prefix='/api')

@app.route('/')
def home():
    token = request.cookies.get('access_token')
    if not token:
        print("No access token found")
        return redirect(url_for('login'))
    
    payload = decode_token(token)
    if not payload:
        print("Invalid access token")
        return redirect(url_for('login'))
    
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if user.exists:
        user_data = user.to_dict()
        return render_template('home.html', role=user_data.get('role'))
    
    print("User not found")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if user.exists:
            user_data = user.to_dict()
            if check_password(password, user_data.get('password')):
                access_token = create_access_token(username)
                refresh_token = create_refresh_token(username)
                store_refresh_token(username, refresh_token)
                response = make_response(redirect(url_for('home')))
                response.set_cookie('access_token', access_token)
                return response
            else:
                print("Password check failed")
                return render_template('login.html', error="Bad username or password")
        else:
            print("User not found")
            return render_template('login.html', error="Bad username or password")

    return render_template('login.html')

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
        user_ref = db.collection('users').document(username)
        user = user_ref.get()
        if user.exists:
            return render_template('signup.html', error="User already exists")
        
        user_ref.set({
            'username': username,
            'password': hashed_password,
            'role': 'user',
            'refresh_token': ''
        })
        return redirect(url_for('login'))
    
    return render_template('signup.html')
    
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token', '', expires=0)
    return response

@app.route('/data')
def data():
    return render_template('data.html')

@app.route('/admin')
def admin():
   return render_template('admin.html')

if __name__ == '__main__':
    app.run(debug=True)
