
from django.contrib import admin
from django.urls import path
from .import views

urlpatterns = [
    path('customer-register', views.UserRegistrationView.as_view(), name='customer-register'),
    path('customer-login', views.UserLoginView.as_view(), name='customer-login'),
    # path('user-list', views.UserListView.as_view(), name='user-list'),
    path('forgot-password', views.PasswordResetRequestView.as_view(), name='forgot_password'),
    path('reset-password', views.PasswordResetConfirmView.as_view(), name='reset_password'),
]
