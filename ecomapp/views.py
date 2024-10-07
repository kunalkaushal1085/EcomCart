from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserSerializer,UserListSerializer,UserDataSerializer,ResetPasswordSerializer
from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from rest_framework.permissions import (
    IsAuthenticated,
    IsAuthenticatedOrReadOnly, AllowAny
)
from django.http import JsonResponse
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.urls import reverse
from django.conf import settings
import uuid
from django.contrib.auth import get_user_model    
from django.utils import timezone
from datetime import timedelta 
from .models import PasswordResetToken
from django.utils.encoding import force_str
from django.contrib.auth import update_session_auth_hash
from ecomapp.db_connection import get_db_handle
import json
from .utils import serialize_objectid
import bcrypt
from datetime import datetime, timedelta
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string



# Create your views here.
def baseurl(request):
    """
    Return a BASE_URL template context for the current request.
    """
    if request.is_secure():
        scheme = "https://"
    else:
        scheme = "http://"

    return scheme + request.get_host()

    
class UserRegistrationView(APIView):
    def post(self, request):
        data = request.data
        print(data,'data++++++++++++')
        email = data.get('email')
        print(email)
        password = data.get('password')
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        username = data.get('username')

        if not email or not password or not first_name or not last_name or not username:
            return Response({"error": "Missing required fields."}, status=status.HTTP_400_BAD_REQUEST)

        db_handle, _ = get_db_handle()  # Get the MongoDB database handle
        user_collection = db_handle.user_collection
        if user_collection.find_one({"email": email}):
            return Response({"error": "User with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user_data = {
            "email": email,
            "password": hashed_password,
            "first_name": first_name,
            "last_name": last_name,
            "username": username
        }
        print(type(user_data),"user data checking in json")
        try:
            result =user_collection.insert_one(user_data)
            user_data['_id'] = result.inserted_id
            # serialized_data = serialize_objectid(user_data)
            serialized_data=UserDataSerializer(user_data)
            return Response({
                "status": status.HTTP_201_CREATED,
                "message": "User registered successfully.",
                "data": serialized_data.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

class UserLoginView(APIView):
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        db_handle, _ = get_db_handle()  # Get the MongoDB database handle
        user_collection = db_handle.user_collection

        # Find the user by email
        user = user_collection.find_one({
            "$or": [
                {"email": email.lower()},
                {"username": email}
            ]
        })
        if user:
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                token = str(uuid.uuid4())
                print(token,"???")
                user_data = {
                    "_id": str(user['_id']),  
                    "email": user['email'],
                    "first_name": user['first_name'],
                    "last_name": user['last_name'],
                    "username": user['username']
                }
                return Response({
                    'status': status.HTTP_200_OK,
                    'message': 'User logged in successfully',
                    'token': token,
                    'user': user_data,
                    'base_url': settings.FRONTEND_URL  # Assuming you have FRONTEND_URL in your settings
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid password'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': 'Invalid email'
            }, status=status.HTTP_400_BAD_REQUEST)
            
            

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')

        if not email:
            return Response({'error': 'Email is required.'}, status=status.HTTP_400_BAD_REQUEST)

        db_handle, _ = get_db_handle()
        user_collection = db_handle.user_collection
        reset_token_collection = db_handle.reset_token_collection

        # Find the user by email
        user = user_collection.find_one({"email": email.lower()})

        if not user:
            return Response({'error': 'No user found with this email.'}, status=status.HTTP_404_NOT_FOUND)
        token = uuid.uuid4().hex
        expiry_time = datetime.now() + timedelta(hours=1)

        # Store token and expiry in the database
        reset_token_collection.update_one(
            {"user_id": user['_id']},
            {"$set": {"token": token, "expiry": expiry_time}},
            upsert=True
        )
        # Construct reset URL
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"

        # Send password reset email
        send_mail(
            'Password Reset Link',
            f'Use the following link to reset your password: {reset_url}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False
        )
        return Response({'message': 'Password reset link sent successfully.'}, status=status.HTTP_200_OK)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            db_handle, _ = get_db_handle()  # Get the MongoDB database handle
            user_collection = db_handle.user_collection
            reset_token_collection = db_handle.reset_token_collection

            # Check if the token is valid and not expired
            token_record = reset_token_collection.find_one({"token": token})
            if not token_record or token_record['expiry'] < datetime.now():
                return Response({'error': 'Invalid or expired token.'}, status=status.HTTP_400_BAD_REQUEST)

            # Find the user associated with the token
            user = user_collection.find_one({"_id": token_record['user_id']})
            if not user:
                return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

            # Hash the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

            # Update the user's password
            user_collection.update_one({"_id": user['_id']}, {"$set": {"password": hashed_password}})

            # Remove the token after successful password reset
            reset_token_collection.delete_one({"token": token})

            return Response({'message': 'Password has been reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    