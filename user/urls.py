from django.contrib.auth.views import LoginView
from django.urls import path
from .views import *
urlpatterns = [
    path('register',UserRegistrationView.as_view(), name='register'),
    path('otp-resend',ResendOTPView.as_view(), name='otp-resend'),
    path('verify',VerifyEmailView.as_view(),name='verify'),
    path('reset-password',ResetPasswordView.as_view(),name='reset-password'),
    path('change-password',ChangePasswordView.as_view(),name='change-password'),
    path('password-login',UserPasswordLoginView.as_view(),name='password-login'),
    path('login',UserPinLoginView.as_view(),name='login'),
    path('set-pin',SetPinView.as_view(),name='set-pin'),
    path('bank-account',BankAccountView.as_view(),name='bank-account'),
    path('test',TestView.as_view(),name='test'),
    path('google-auth',GoogleAuthView.as_view(),name='google-auth'),
    path('change-device',ChangeDeviceView.as_view(),name='change-device'),
    path('friends',FriendView.as_view(),name='friends'),
    path('groups',GroupView.as_view(),name='groups'),
    path('groups/<int:id>',SpecificGroupView.as_view(),name='specific-group'),
    path('get',GetUser.as_view(),name='get-user'),

]