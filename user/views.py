from datetime import timezone
from random import random

from django.core.validators import validate_email
from django.db import transaction
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from .models import *
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.views import APIView
from .serializers import *
from helpers import encryption_helper, otp
from mailer import mailer

class UserRegistrationView(APIView):
    def post(self, request):
        body = request.data
        serializer = UserRegistrationSerializer(data=body)
        if not serializer.is_valid():
            return Response({
                'message':'Invalid input',
                'errors': serializer.errors,
            }, status= status.HTTP_422_UNPROCESSABLE_ENTITY)
        hashed_password = encryption_helper.hash(serializer.data['password'])
        hashed_pin = encryption_helper.hash(str(serializer.data['pin']))
        with transaction.atomic():
            user = User.objects.create(first_name=serializer.data['first_name'], last_name=serializer.data['last_name'],email=serializer.data['email'],password=hashed_password,pin=hashed_pin,username=serializer.data['username'],phoneNumber=serializer.data['phoneNumber'])
            user_otp = otp.generate_top(user)
            mailer.send_email(serializer.data['first_name'], serializer.data['email'], user_otp)
            return Response({
                'status': 'success',
                'message': 'User registered successfully. An OTP has been sent to mail',
            })

class ResendOTPView(APIView):
    def post(self, request):
        body = request.data
        if not body['email'] or not isinstance(body['email'], str):
            return Response({
                'message':'email is required'
            })
        try:
            validate_email(body['email'])
        except ValidationError:
            return Response({
                'message':'email is invalid'
            }, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=body['email'])
            ava_otp = UserOTP.objects.get(user=user)
            if ava_otp:
                if ava_otp.otp == None:
                    return Response({
                        'message': 'User has been verififed, proceed to login'
                    })
                else:
                    ava_otp.otp = otp.generate_otp(user)
                    ava_otp.otp_created_at = timezone.now()
                    ava_otp.save()
                    mailer.send_otp_mail(user.firstName, user.email, ava_otp.otp)
                    return Response({
                        'status': 'success',
                        'message': 'OTP sent successfully',
                    }, status=status.HTTP_200_OK)
            else:
                new_otp = otp.generate_otp(user)
                mailer.send_otp_mail(user.firstName, user.email, new_otp)
                return Response({
                    'status': 'success',
                    'message': 'OTP sent successfully',
                }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                'message':'email is not registered on the app'
            })
# class VerifyOTPView

