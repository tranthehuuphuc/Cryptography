from django.contrib import admin
from django.urls import path
from myapp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.login_page, name='login_page'),
    path('login/', views.login, name='login'),
    path('api_call/', views.api_call, name='api_call'),
]
