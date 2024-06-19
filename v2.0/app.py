from flask import Flask, render_template, redirect, url_for, request, current_app, make_response
from controllers.auth_controller import auth_bp
from controllers.api_controller import api_bp
from utils.jwt_helper import decode_token
from config import db

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(api_bp, url_prefix='/api')

@app.route('/')
def home():
    token = request.cookies.get('access_token')
    if not token:
        return redirect(url_for('auth.login'))
    
    payload = decode_token(token)
    if not payload:
        return redirect(url_for('auth.login'))
    
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if user.exists:
        user_data = user.to_dict()
        return render_template('home.html', role=user_data.get('role'))
    
    return redirect(url_for('auth.login'))

@app.route('/data')
def data():
    token = request.cookies.get('access_token')
    if not token:
        return redirect(url_for('auth.login'))
    
    payload = decode_token(token)
    if not payload:
        return redirect(url_for('auth.login'))
    
    return render_template('data.html')

@app.route('/admin')
def admin():
    token = request.cookies.get('access_token')
    if not token:
        return redirect(url_for('auth.login'))
    
    payload = decode_token(token)
    if not payload:
        return redirect(url_for('auth.login'))
    
    username = payload['sub']
    user_ref = db.collection('users').document(username)
    user = user_ref.get()
    if user.exists and user.to_dict().get('role') == 'admin':
        return render_template('admin.html')
    
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('auth.login')))
    response.set_cookie('access_token', '', expires=0)
    response.set_cookie('refresh_token', '', expires=0)
    return response

if __name__ == '__main__':
    app.run(debug=True)