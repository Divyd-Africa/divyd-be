from django.core.validators import validate_email
from django.db import transaction, IntegrityError
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from Divyd_be import settings
from .models import *
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.views import APIView
from .serializers import *
from helpers import encryption_helper, otp, kora_functions
from mailer import mailer
from wallet.views import createWallet
from google.oauth2 import id_token as g_id_token
from google.auth.transport import requests as g_requests
def unique_username_from_email(email):
    base = email.split('@')[0]
    username = base
    suffix = 1
    while User.objects.filter(username=username).exists():
        username = base + str(suffix)
        suffix += 1
    return username

def mark_verified(user):
    user.is_email_verified = True
    update_last_login(user.email)
    user.save(update_fields=['is_email_verified'])

    otp_obj,_= UserOTP.objects.get_or_create(user=user)
    otp_obj.otp = None
    otp_obj.save(update_fields=['otp'])
def update_last_login(email):
    user = User.objects.get(email=email)
    user.last_login = timezone.now()
    user.save()

class GoogleAuthView(APIView):
    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Token is missing'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            idinfo = g_id_token.verify_oauth2_token(token,g_requests.Request())
            if idinfo.get("aud") != settings.GOOGLE_CLIENT_ID:
                return Response({"message": "Invalid audience for Google token"}, status=400)
            if idinfo.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
                return Response({"message": "Invalid issuer for Google token"}, status=400)
            if not idinfo.get("email"):
                return Response({"message": "Google token missing email scope"}, status=400)
            email = idinfo["email"]
            first_name = idinfo.get("given_name", "") or ""
            last_name = idinfo.get("family_name", "") or ""
            user, created = User.objects.get_or_create(email=email,
                                                       defaults={
                                                           "firstName": first_name,
                                                           "lastName": last_name,
                                                           "username": unique_username_from_email(email),
                                                       })
            if created and not user.password:
                user.set_unusable_password()
                user.save(update_fields=['password'])
                mark_verified(user)
            token = RefreshToken.for_user(user)
            access_token = str(token.access_token)
            return Response({
                "message":"Registration successful",
                "user": UserSerializer(user).data,
                "access_token": access_token,
            },status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserRegistrationView(APIView):
    def post(self, request):
        body = request.data
        serializer = UserRegistrationSerializer(data=body)
        if not serializer.is_valid():
            return Response({
                'message':'Invalid input',
                'errors': serializer.errors,
            }, status= status.HTTP_422_UNPROCESSABLE_ENTITY)
        try:
            user = User.objects.get(email=serializer.data['email'])
            return Response({
                'message':'Email already exists',
            },status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            try:
                username = User.objects.get(username=serializer.data['username'])
                return Response({
                    'message':'Username already exists',
                },status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                hashed_password = encryption_helper.hash(serializer.data['password'])
                with transaction.atomic():
                    user = User.objects.create(firstName=serializer.data['firstName'], lastName=serializer.data['lastName'],email=serializer.data['email'],password=hashed_password,username=serializer.data['username'],phoneNumber=serializer.data['phoneNumber'])
                    user_otp = otp.generate_otp(user)
                    createWallet(user)
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
            if user.is_email_verified == True:
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
            if user.is_email_verified == True:
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


class BankAccountView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        banks = kora_functions.get_all_banks()
        return Response({
            'status': 'success',
            'message': 'Banks found',
            'banks': banks
        })
    def post(self, request):
        body = request.data
        user = request.user
        if not body['account'] or not isinstance(body['account'], str):
            return Response({
                'message':'Account is required'
            },status=status.HTTP_400_BAD_REQUEST)
        if not body['bank'] or not isinstance(body['bank'], str):
            return Response({
                'message':'Bank Code is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        if not body['bank_name'] or not isinstance(body['bank_name'], str):
            return Response({
                'message':'Bank Name is required'
            },status=status.HTTP_400_BAD_REQUEST)
        valid_account = kora_functions.verify_bank_details(body['bank'], body['account'])
        if valid_account['status']:
            try:
                user = User.objects.get(email=user.email)
            except User.DoesNotExist:
                return Response({
                    'message':'User not found'
                },status=status.HTTP_404_NOT_FOUND)
            try:
                user_bank = UserBank.objects.create(user=user,bank_code=body['bank'],bank_name=body['bank_name'],account_number=body['account'])
                return Response({
                    'status': 'success',
                    'message': 'Bank account saved',
                    'details':valid_account['data']
                },status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({
                    'message':'Bank account already set for user, update account details'
                },status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({
                    'message':f'Bank account creation failed with {e}',
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                'message':'Bank Account is invalid'
            },status=status.HTTP_400_BAD_REQUEST)

    def put(self, request):
        body = request.data
        user = request.user
        if not body['account'] or not isinstance(body['account'], str):
            return Response({
                'message':'Account is required'
            },status=status.HTTP_400_BAD_REQUEST)
        if not body['bank'] or not isinstance(body['bank'], str):
            return Response({
                'message':'Bank Code is required'
            },status=status.HTTP_400_BAD_REQUEST)
        if not body['bank_name'] or not isinstance(body['bank_name'], str):
            return Response({
                'message':'Bank Name is required'
            },status=status.HTTP_400_BAD_REQUEST)
        valid_account = kora_functions.verify_bank_details(body['bank'], body['account'])
        if valid_account['status']:
            try:
                bank_det = UserBank.objects.get(user=user)
            except UserBank.DoesNotExist:
                return Response({
                    'message':"You do not have any bank account saved"
                },status=status.HTTP_404_NOT_FOUND)
            bank_det.bank_code = body['bank']
            bank_det.bank_name = body['bank_name']
            bank_det.account_number = body['account']
            bank_det.save()
            return Response({
                'status': 'success',
                'message': 'Bank account saved',
                'details':valid_account['data']
            },status=status.HTTP_200_OK)
        else:
            return Response({
                'message':'Bank Account is invalid',
                'response':valid_account['data']
            },status=status.HTTP_400_BAD_REQUEST)

class TestView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user
        response = kora_functions.generate_temp_account(5000,user)
        return Response({
            'response':response
        })
