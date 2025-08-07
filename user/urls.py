from django.urls import path
from .views import *
urlpatterns = [
    path('register',UserRegistrationView.as_view(), name='register'),
    path('otp-resend',ResendOTPView.as_view(), name='otp-resend'),
]