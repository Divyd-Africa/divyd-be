from django.db import transaction
from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import *
from .tasks import *
User = get_user_model()

def calculate_next_date(frequency):
    if frequency == "monthly":
        return now() + relativedelta(months=1)
    elif frequency == "weekly":
        return now() + relativedelta(weeks=1)
    elif frequency == "yearly":
        return now() + relativedelta(years=1)
    elif frequency == "daily":
        return now() + relativedelta(days=1)


class BillSplitInputSerializer(serializers.Serializer):
    user = serializers.CharField()  # username or email
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, required=False)
    percent = serializers.DecimalField(max_digits=5, decimal_places=2, required=False)

class ReBillCreateSerializer(serializers.ModelSerializer):
    participants = serializers.ListField(
        child=serializers.CharField(), write_only=True, required=False
    )
    splits = BillSplitInputSerializer(many=True, required=False, write_only=True)

    class Meta:
        model = RecurringBill
        fields = ["frequency", "participants","splits"]

    def create(self, validated_data):
        user = self.context["request"].user

        with transaction.atomic():
            bill_serializer = BillCreateSerializer(data={
                "created_by":user,
                "title": self.context["request"].data.get("title"),
                "description": self.context["request"].data.get("description", ""),
                "total_amount": self.context["request"].data.get("total_amount"),
                "split_type": self.context["request"].data.get("split_type"),
                "participants": validated_data.get("participants", []),
                "splits": validated_data.get("splits", []),
            },context=self.context)
            bill_serializer.is_valid(raise_exception=True)
            bill = bill_serializer.save()

            recurring_bill = RecurringBill.objects.create(
                bill=bill,
                creator=user,
                amount=self.context["request"].data.get("total_amount"),
                frequency=self.context["request"].data.get("frequency"),
                next_run= calculate_next_date(validated_data["frequency"]),
                is_active=True
            )
            for split in bill.splits.all():
                if not split.is_creator:
                    RecurringBillParticipant.objects.create(
                        recurring_bill=recurring_bill,
                        user=split.user,
                        amount=split.amount,
                        status="pending",
                        missed_cycles=1
                    )
            return recurring_bill

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
                    bill_split = BillSplit.objects.create(
                        bill=bill,
                        user=u,
                        amount=share,
                        status="paid" if u == user else "pending",
                        is_creator=(u == user),
                    )
                    bill_data = BillSplitSerializer(bill_split).data
                    if u != user:
                        send_new_bill_alert.delay(user.id, u.id, bill_data)


            elif split_type == "custom_amount":
                total_check = 0
                for split in validated_data["splits"]:
                    u = User.objects.get(username=split["user"])
                    amt = split["amount"]
                    total_check += amt
                    if total_check > total_amount:
                        raise serializers.ValidationError("Custom amounts cannot exceed total bill amount.")
                    bill_split = BillSplit.objects.create(
                        bill=bill,
                        user=u,
                        amount=amt,
                        status="paid" if u == user else "pending",
                        is_creator=(u == user),
                    )
                    bill_data = BillSplitSerializer(bill_split).data
                    if u != user:
                        send_new_bill_alert.delay(user.id, u.id, bill_data)


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
                    bill_split = BillSplit.objects.create(
                        bill=bill,
                        user=u,
                        amount=amt,
                        status="paid" if u == user else "pending",
                        is_creator=(u == user),
                    )
                    bill_data = BillSplitSerializer(bill_split).data
                    if u != user:
                        send_new_bill_alert.delay(user.id,u.id,bill_data)
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
        fields = ["id", "username", "email"]
        # adjust to your User model

class SecBillSerializer(serializers.ModelSerializer):
    created_by = UserSerializer(read_only=True)
    class Meta:
        model = Bill
        fields = ["title","total_amount","id","created_by"]

class BillSplitSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # show user details, not just ID
    bill = SecBillSerializer(read_only=True)
    class Meta:
        model = BillSplit
        fields = ["id", "user", "amount", "status", "is_creator", "updated_at","bill"]


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

class ReBillSerializer(serializers.ModelSerializer):
    participants = serializers.SerializerMethodField()
    creator = UserSerializer(read_only=True)

    class Meta:
        model = RecurringBill
        fields = ["id", "creator", "amount", "frequency", "next_run", "is_active", "created_at", "bill", "participants"]

    def get_participants(self, obj):
        return [
            {
                "user": p.user.username,
                "amount": p.amount,
                "status": p.status,
            }
            for p in obj.recurringbillparticipant_set.all()
        ]

class ParticipantSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = RecurringBillParticipant
        fields = "__all__"