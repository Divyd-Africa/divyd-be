from user.models import *
from random import random

def generate_otp(user):
    otp_string = random.randint(100000, 999999)
    UserOTP.objects.create(user=user, otp=otp_string)
    return otp_string