from django.shortcuts import render
from django.http import JsonResponse
import requests
import logging
from firebase_admin import credentials, initialize_app, firestore

logger = logging.getLogger(__name__)

# Initialize Firebase
cred = credentials.Certificate("D:/credentials.json")
initialize_app(cred)
db = firestore.client()

def login_page(request):
    return render(request, 'login.html')

def login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            return JsonResponse({'message': 'Username and password are required'}, status=400)

        server_url = 'http://localhost:5000/login'
        payload = {'username': username, 'password': password}
        response = requests.post(server_url, json=payload)

        if response.status_code == 200:
            token = response.json().get('token')
            request.session['token'] = token
            request.session.modified = True
            logger.info(f"Django session after login: {dict(request.session.items())}")
            return JsonResponse({'message': 'Login successful', 'token': token})
        else:
            error_message = response.json().get('message')
            return JsonResponse({'message': f'Login failed: {error_message}'}, status=response.status_code)

    return JsonResponse({'message': 'Method not allowed'}, status=405)


def api_call(request):
    if request.method == 'GET':
        token = request.session.get('token')
        logger.info(f"Session before API call: {request.session.items()}")
        if not token:
            logger.error('No token found in session')
            return JsonResponse({'message': 'Unauthorized'}, status=401)

        server_url = 'http://localhost:5001/api_gateway'
        headers = {'Authorization': f'Bearer {token}'}
        try:
            response = requests.get(server_url, headers=headers)
            if response.status_code == 200:
                role = response.json().get('role')
                if role == 'admin':
                    users = [doc.to_dict() for doc in db.collection('users').stream()]
                    return JsonResponse({'users': users}, status=200)
                else:
                    return JsonResponse({'message': 'Forbidden'}, status=403)
            else:
                return JsonResponse({'message': 'Failed to get role from server'}, status=response.status_code)
        except requests.exceptions.HTTPError as http_err:
            logger.error(f'HTTP error occurred: {http_err}')
            return JsonResponse({'message': 'Failed to get users'}, status=response.status_code)
        except Exception as err:
            logger.error(f'Other error occurred: {err}')
            return JsonResponse({'message': 'Failed to get users'}, status=500)
    return JsonResponse({'message': 'Method not allowed'}, status=405)
