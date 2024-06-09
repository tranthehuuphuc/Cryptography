import requests
import bcrypt
from django.shortcuts import render
from django.http import JsonResponse

def login_page(request):
    return render(request, 'login.html')

def login(request):
    if request.method == 'POST':
        # Lấy thông tin đăng nhập từ form
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not username or not password:
            return JsonResponse({'message': 'Username and password are required'}, status=400)
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Gửi yêu cầu POST đến endpoint login trên server Flask
        server_url = 'http://localhost:5000/login'  # Thay đổi địa chỉ server tương ứng
        payload = {'username': username, 'password': hashed_password.decode('utf-8')}
        response = requests.post(server_url, json=payload)

        # Xử lý kết quả từ server Flask
        if response.status_code == 200:
            token = response.json().get('token')
            return JsonResponse({'message': 'Login successful', 'token': token})
        else:
            error_message = response.json().get('message')
            return JsonResponse({'message': f'Login failed: {error_message}'}, status=response.status_code)

    return JsonResponse({'message': 'Method not allowed'}, status=405)
