from rest_framework import serializers
from .models import *

class BillSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bill
        fields = ["id", "title", "description", "total_amount", "created_at"]

class BillParticipantSerializer(serializers.ModelSerializer):
    user = serializers.CharField(source="user.username")

    class Meta:
        model = BillSplit
        fields = ["user", "amount", "status", "is_creator"]


class BillListSerializer(serializers.ModelSerializer):
    my_share = serializers.SerializerMethodField()
    amount_owed_to_me = serializers.SerializerMethodField()
    amount_i_owe = serializers.SerializerMethodField()

    class Meta:
        model = Bill
        fields = ["id", "title", "total_amount", "created_at",
                  "my_share", "amount_owed_to_me", "amount_i_owe"]

    def get_my_share(self, obj):
        """Show how much THIS user owes in this bill"""
        user = self.context["request"].user
        split = obj.splits.filter(user=user).first()
        return split.amount if split else None

    def get_amount_owed_to_me(self, obj):
        """If I am the creator, show how much others still owe me"""
        user = self.context["request"].user
        if obj.created_by != user:
            return 0
        return sum(s.amount for s in obj.splits.exclude(user=user).filter(status__in=["pending", "approved"]))

    def get_amount_i_owe(self, obj):
        """If I’m just a participant, show what I still owe"""
        user = self.context["request"].user
        split = obj.splits.filter(user=user, status__in=["pending", "approved"]).first()
        return split.amount if split else 0


class BillDetailSerializer(serializers.ModelSerializer):
    participants = BillParticipantSerializer(source="splits", many=True)
    my_share = serializers.SerializerMethodField()

    class Meta:
        model = Bill
        fields = ["id", "title", "description", "total_amount",
                  "created_at", "my_share", "participants"]

    def get_my_share(self, obj):
        user = self.context["request"].user
        split = obj.splits.filter(user=user).first()
        return split.amount if split else None