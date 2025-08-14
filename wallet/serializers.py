from rest_framework import serializers
from wallet.models import *


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['user','balance']
