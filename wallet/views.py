from django.shortcuts import render
from .models import *
# Create your views here.
def createWallet(user):
    Wallet.objects.create(user=user)