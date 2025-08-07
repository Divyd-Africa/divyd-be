from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
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
            user = User.objects.create(firstName=serializer.data['firstName'], lastName=serializer.data['lastName'],email=serializer.data['email'],password=hashed_password,pin=hashed_pin,username=serializer.data['username'],phoneNumber=serializer.data['phoneNumber'])
            user_otp = otp.generate_otp(user)
            mailer.send_otp_mail(serializer.data['firstName'], serializer.data['email'], user_otp)
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
class VerifyEmailView(APIView):
    def put(self, request):
        body = request.data
        if not body['email'] or not isinstance(body['email'], str):
            return Response({
                'message':'email is required'
            },status=status.HTTP_400_BAD_REQUEST)
        if not body['otp'] or not isinstance(body['otp'], int):
            return Response({
                'message':'otp is required'
            },status=status.HTTP_400_BAD_REQUEST)
        try:
            validate_email(body['email'])
        except ValidationError:
            return Response({
                'message':'email is invalid'
            },status=status.HTTP_400_BAD_REQUEST)
        try:
            input_otp = int(body['otp'])
            print(input_otp)
            user = User.objects.get(email=body['email'])
            valid, message = otp.verify_otp(user, input_otp)
            if valid == False:
                return Response({
                    'message':message
                },status=status.HTTP_400_BAD_REQUEST)
            else:
                user.is_email_verified = True
                user.save()
                return Response({
                    'status': 'success',
                    'message': 'Email verified successfully'
                },status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                'message':'email is not registered on the app'
            },status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    def post(self, request):
        body = request.data
        if not body['otp'] or not isinstance(body['otp'], int):
            return Response({
                'message':'otp is required'
            },status=status.HTTP_400_BAD_REQUEST)
        if not body['email'] or not isinstance(body['email'], str):
            return Response({
                'message':'email is required'
            },status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=body['email'])
            valid, message = otp.verify_otp(user, body['otp'])
            if valid == False:
                return Response({
                    'message':message
                }, status=status.HTTP_400_BAD_REQUEST)
            else:
                token = AccessToken.for_user(user)
                return Response({
                    'status': 'success',
                    'message':'OTP valid',
                    'token': str(token),
                })
        except Exception as e:
            return Response({
                'message':str(e)
            })

    def put(self, request):
        body = request.data
        token = request.query_params.get('token','').strip()
        if not token:
            return Response({
                'message':'token is required'
            })
        try:
            access_token = AccessToken(token)
            userId = access_token['user_id']
        except Exception as e:
            return Response({
                'message':str(e)
            },status=status.HTTP_400_BAD_REQUEST)
        if not body['new_password'] or not isinstance(body['new_password'], str):
            return Response({
                'message':'new_password is required'
            },status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['confirm'] or not isinstance(body['confirm'], str):
            return Response({
                'message':'confirm is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            user = User.objects.get(pk=userId)
            if body['new_password'] != body['confirm']:
                return Response({
                    'message':'passwords do not match'
                }, status = status.HTTP_400_BAD_REQUEST)
            user.password = encryption_helper.hash(body['new_password'])
            user.save()
            return Response({
                'status': 'success',
                'message': 'Password updated successfully'
            }, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({
                'message':'Invalid Id'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message':str(e)
            }, status= status.HTTP_500_INTERNAL_SERVER_ERROR)


