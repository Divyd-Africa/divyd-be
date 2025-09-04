from django.db import transaction
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *

User = get_user_model()


class BillSplitInputSerializer(serializers.Serializer):
    user = serializers.CharField()  # username or email
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, required=False)
    percent = serializers.DecimalField(max_digits=5, decimal_places=2, required=False)


class BillCreateSerializer(serializers.ModelSerializer):
    participants = serializers.ListField(
        child=serializers.CharField(), write_only=True, required=False
    )
    splits = BillSplitInputSerializer(many=True, write_only=True, required=False)

    class Meta:
        model = Bill
        fields = ["title", "description", "total_amount", "split_type", "participants", "splits"]

    def create(self, validated_data):
        user = self.context["request"].user
        split_type = validated_data["split_type"]
        total_amount = validated_data["total_amount"]

        # create bill
        with transaction.atomic():
            bill = Bill.objects.create(
                created_by=user,
                title=validated_data["title"],
                description=validated_data.get("description", ""),
                total_amount=total_amount,
                split_type=split_type,
            )

            # include creator always
            participants = []
            if split_type == "equal":
                participants = validated_data.get("participants", [])
            else:
                participants = [split["user"] for split in validated_data.get("splits", [])]

            # resolve users
            users = []
            for username in participants:
                try:
                    u = User.objects.get(username=username)
                    users.append(u)
                except User.DoesNotExist:
                    raise serializers.ValidationError(f"User {username} not found")

            # add creator as participant
            all_users = [user] + users

            # create splits
            if split_type == "equal":
                share = total_amount / len(all_users)
                for u in all_users:
                    BillSplit.objects.create(
                        bill=bill,
                        user=u,
                        amount=share,
                        status="paid" if u == user else "pending",
                        is_creator=(u == user),
                    )


            elif split_type == "custom_amount":
                total_check = 0
                for split in validated_data["splits"]:
                    u = User.objects.get(username=split["user"])
                    amt = split["amount"]
                    total_check += amt
                    if total_check > total_amount:
                        raise serializers.ValidationError("Custom amounts cannot exceed total bill amount.")
                    BillSplit.objects.create(
                        bill=bill,
                        user=u,
                        amount=amt,
                        status="paid" if u == user else "pending",
                        is_creator=(u == user),
                    )

                # If total is less, assign remainder to creator

                creator_share = total_amount - total_check
                if creator_share > 0:
                    BillSplit.objects.create(
                        bill=bill,
                        user=user,
                        amount=creator_share,
                        status="paid",
                        is_creator=True,
                    )
            elif split_type == "custom_percent":
                total_percent = 0
                for split in validated_data["splits"]:
                    u = User.objects.get(username=split["user"])
                    pct = split["percent"]
                    total_percent += pct
                    if total_percent > 100:
                        raise serializers.ValidationError("Custom percentages cannot exceed 100.")
                    amt = (pct / 100) * total_amount
                    BillSplit.objects.create(
                        bill=bill,
                        user=u,
                        amount=amt,
                        status="paid" if u == user else "pending",
                        is_creator=(u == user),
                    )
                # If total is less than 100, creator takes the remainder
                if total_percent < 100:
                    creator_share = (100 - total_percent) / 100 * total_amount
                    BillSplit.objects.create(
                        bill=bill,
                        user=user,
                        amount=creator_share,
                        status="paid",
                        is_creator=True,
                    )
                # creator gets nothing extra (unless you want him included too in %)
            return bill

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email"]  # adjust to your User model


class BillSplitSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # show user details, not just ID

    class Meta:
        model = BillSplit
        fields = ["id", "user", "amount", "status", "is_creator", "updated_at"]


class SingleBillSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    splits = BillSplitSerializer(many=True, read_only=True)
    total_paid = serializers.SerializerMethodField()
    total_pending = serializers.SerializerMethodField()
    participants_status = serializers.SerializerMethodField()

    class Meta:
        model = Bill
        fields = [
            "id",
            "title",
            "description",
            "total_amount",
            "split_type",
            "created_by",
            "created_at",
            "total_paid",
            "total_pending",
            "participants_status",
            "splits",  # show all participant splits with user info
        ]

    def get_total_paid(self, obj):
        return obj.total_paid()

    def get_total_pending(self, obj):
        return obj.total_pending()

    def get_participants_status(self, obj):
        return obj.participants_status()


class BillSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    total_paid = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)
    total_pending = serializers.DecimalField(max_digits=12, decimal_places=2, read_only=True)

    class Meta:
        model = Bill
        fields = [
            "id",
            "title",
            "description",
            "total_amount",
            "split_type",
            "created_by",
            "created_at",
            "total_paid",
            "total_pending",
        ]