from django.urls import path
from .views import *
urlpatterns = [
    path('register',UserRegistrationView.as_view(), name='register'),
    path('otp-resend',ResendOTPView.as_view(), name='otp-resend'),
    path('verify',VerifyEmailView.as_view(),name='verify'),
    path('reset-password',ResetPasswordView.as_view(),name='reset-password'),
]