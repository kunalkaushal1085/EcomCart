from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.response import Response
import logging
# from bson import ObjectId

logger = logging.getLogger(__name__)



############ fetch data frim mongo db

class UserSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=100)
    last_name = serializers.CharField(max_length=100)
    username = serializers.CharField(max_length=100)
    _id = serializers.SerializerMethodField()  # Custom field to handle ObjectId

    def get__id(self, obj):
        return str(obj.get('_id'))  # Convert ObjectId to string

    # def to_representation(self, instance):
    #     """
    #     Convert the MongoDB document to a JSON serializable format.
    #     """
    #     ret = super().to_representation(instance)
    #     # Convert ObjectId to string for the _id field
    #     if isinstance(instance.get('_id'), ObjectId):
    #         ret['_id'] = str(instance['_id'])
    #     return ret


class UserDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = ['id','username', 'first_name', 'last_name', 'email', 'password']
        fields = ['first_name', 'last_name', 'email', 'password','username']
        extra_kwargs = {'password': {'write_only': True}}
        
    
    def validate_email(self, value):
        """
        Check if the email address is unique.
        """
        try:
            email_exists = User.objects.filter(email=value).exists()
            if email_exists:
                raise serializers.ValidationError('This email address is already in use.')
        except Exception as e:
            # Log or print the exception for debugging
            print(f"Error during email validation: {e}")  # Print full error details
            # raise serializers.ValidationError('An error occurred during validation.')
            raise serializers.ValidationError('This email address is already in use.')
        return value
    
    def create(self, validated_data):
        email = validated_data.pop('email')
        username = email.split('@')[0]
        
        # Create user with email and password
        user = User.objects.create_user(username=username, email=email, **validated_data)  # Include email
        
        if 'is_staff' in validated_data:
            user.is_staff = validated_data['is_staff']
        
        return user


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name','is_staff']


class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()
    confirm_password = serializers.CharField()

    def validate(self, data):
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match.")
        return data