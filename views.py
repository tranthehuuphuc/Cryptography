from django.shortcuts import render
from django.http import JsonResponse
import requests

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
            return JsonResponse({'message': 'Login successful', 'token': token})
        else:
            error_message = response.json().get('message')
            return JsonResponse({'message': f'Login failed: {error_message}'}, status=response.status_code)

    return JsonResponse({'message': 'Method not allowed'}, status=405)

def call_api(token):
    if not token:
        return JsonResponse({'message': 'Unauthorized'}, status=401)
    
    # Define the URL of the API gateway endpoint
    api_gateway_url = 'http://localhost:5001/api_gateway'

    # Set the authorization header with the token
    headers = {'Authorization': token}

    # Make a GET request to the API gateway endpoint
    response = requests.get(api_gateway_url, headers=headers)

    # Check the response status code
    if response.status_code == 200:
        # If the request was successful, return the response JSON
        return response.json()
    else:
        # If there was an error, print the error message
        print(f"Error: {response.status_code} - {response.text}")
        return None