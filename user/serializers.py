from rest_framework import serializers
from .models import *

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['firstName', 'lastName', 'username', 'email', 'is_email_verified','phoneNumber']


class UserRegistrationSerializer(serializers.Serializer):
    firstName = serializers.CharField()
    lastName = serializers.CharField()
    email = serializers.EmailField()
    password = serializers.CharField()
    username = serializers.CharField()
    phoneNumber = serializers.CharField()

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 6 characters long.")
        return value

class UserBankSerializer(serializers.Serializer):
    class Meta:
        model = UserBank
        fields = '__all__'

class FriendSerializer(serializers.ModelSerializer):
    friend = UserSerializer(read_only=True)
    class Meta:
        model = Friend
        fields = ['id','friend']

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = '__all__'

class GroupMemberSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = GroupMember
        fields = ['id','user']