from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import *
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.views import APIView
from .serializers import *
from helpers import encryption_helper, otp
from mailer import mailer

def update_last_login(email):
    user = User.objects.get(email=email)
    user.last_login = timezone.now()
    user.save()
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
        with transaction.atomic():
            user = User.objects.create(firstName=serializer.data['firstName'], lastName=serializer.data['lastName'],email=serializer.data['email'],password=hashed_password,username=serializer.data['username'],phoneNumber=serializer.data['phoneNumber'])
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
                token = RefreshToken.for_user(user)
                return Response({
                    'status': 'success',
                    'message':'OTP valid',
                    'token': str(token.access_token),
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

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request):
        user = request.user
        body = request.data
        if not body['old_password'] or not isinstance(body['old_password'], str):
            return Response({
                'message':'new_password is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['new_password'] or not isinstance(body['new_password'], str):
            return Response({
                'message':'new_password is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['confirm_password'] or not isinstance(body['confirm_password'], str):
            return Response({
                'message':'new_password is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if encryption_helper.verify_hash(body['old_password'],user.password):
            if body['new_password'] == body['confirm_password']:
                user.password = encryption_helper.hash(body['new_password'])
                user.save()
                return Response({
                    'status': 'success',
                    'message': 'Password updated successfully'
                },status=status.HTTP_200_OK)
            else:
                return Response({
                    'message':'passwords do not match'
                }, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                'message':'Old password is incorrect'
            },status=status.HTTP_403_FORBIDDEN)

class SetPinView(APIView):
    def put(self, request):
        body = request.data
        if not body['email'] or not isinstance(body['email'], str):
            return Response({
                'message':'email is required'
            },status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['pin'] or not isinstance(body['pin'], int):
            return Response({
                'message':'pin is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['confirm_pin'] or not isinstance(body['confirm_pin'], int):
            return Response({
                'message':'confirm_pin is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            validate_email(body['email'])
            user = User.objects.get(email=body['email'])
        except ValidationError or User.DoesNotExist:
            return Response({
                'message':'Invalid email'
            },status=status.HTTP_400_BAD_REQUEST)
        if body['pin'] == body['confirm_pin']:
            user.pin = encryption_helper.hash(str(body['pin']))
            user.save()
            return Response({
                'status': 'success',
                'message': 'Pin set successfully'
            },status=status.HTTP_200_OK)
        else:
            return Response({
                'message':'pins do not match'
            }, status=status.HTTP_400_BAD_REQUEST)

class UserPasswordLoginView(APIView):
    def post(self, request):
        body = request.data
        if not body['email'] or not isinstance(body['email'], str):
            return Response({
                'message':'Email is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['password'] or not isinstance(body['password'], str):
            return Response({
                'message':'Password is required'
            , }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            user = User.objects.get(email=body['email'])
            user_otp = UserOTP.objects.get(user=user)
            if user_otp and user_otp.otp == None:
                if encryption_helper.verify_hash(str(body['password']),user.password):
                    token = RefreshToken.for_user(user)
                    access_token = str(token.access_token)
                    update_last_login(user.email)
                    return Response({
                        'status': 'success',
                        'message':'Login Successful',
                        'user':UserSerializer(user).data,
                        'access_token':access_token,
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'message':'Incorrect Password'
                    }, status=status.HTTP_403_FORBIDDEN)
            else:
                return Response({
                    'message':'Email is not verified'
                }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({
                'message':'Email is not registered on the app'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message':str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserPinLoginView(APIView):
    def post(self, request):
        body = request.data
        if not body['email'] or not isinstance(body['email'], str):
            return Response({
                'message':'Email is required'
            }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        if not body['pin'] or not isinstance(body['pin'], int):
            return Response({
                'message':'Password is required'
            , }, status=status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            user = User.objects.get(email=body['email'])
            user_otp = UserOTP.objects.get(user=user)
            if user_otp and user_otp.otp == None:
                if encryption_helper.verify_hash(str(body['pin']),user.pin):
                    token = RefreshToken.for_user(user)
                    access_token = str(token.access_token)
                    update_last_login(user.email)
                    return Response({
                        'status': 'success',
                        'message':'Login Successful',
                        'user':UserSerializer(user).data,
                        'access_token':access_token,
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        'message':'Incorrect Pin'
                    }, status=status.HTTP_403_FORBIDDEN)
            else:
                return Response({
                    'message':'Email is not verified'
                }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            return Response({
                'message':'Email is not registered on the app'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'message':str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


