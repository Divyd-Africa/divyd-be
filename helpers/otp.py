from datetime import timedelta
from django.utils import timezone

from user.models import *
import random

def generate_otp(user):
    otp_string = random.randint(100000, 999999)
    try:
        UserOTP.objects.create(user=user, otp=otp_string)
        return otp_string
    except Exception as e:
        return otp_string

def verify_otp(user, otp):
    try:
        otp_instance = UserOTP.objects.get(user=user, otp=otp)

        # Check if expired
        if otp_instance.otp_created_at + timedelta(minutes=5) < timezone.now():
            return False, "OTP has expired"

        return True, "OTP is valid"

    except UserOTP.DoesNotExist:
        return False, "Invalid OTP"

