from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid


class Bill(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="bills_created"
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.title} - {self.total_amount}"

    def total_paid(self):
        return sum(split.amount for split in self.splits.filter(status="paid"))

    def total_pending(self):
        return sum(split.amount for split in self.splits.filter(status__in=["pending", "approved"]))

    def participants_status(self):
        """Returns a summary of all participants with their payment status"""
        return [
            {
                "user": split.user.username,
                "amount": split.amount,
                "status": split.status,
            }
            for split in self.splits.all()
        ]


class BillSplit(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending Approval"),  # User hasn't accepted
        ("approved", "Approved, awaiting debit"),
        ("paid", "Paid"),
        ("declined", "Declined"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    bill = models.ForeignKey(
        Bill,
        on_delete=models.CASCADE,
        related_name="splits"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="bill_splits"
    )
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    is_creator = models.BooleanField(default=False)  # True if this entry is for the bill creator
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user} owes {self.amount} for {self.bill}"


class SplitHistory(models.Model):
    ACTION_CHOICES = (
        ("created", "Bill Created"),
        ("approval", "Approval"),
        ("debit", "Wallet Debit"),
        ("paid", "Marked as Paid"),
        ("decline", "Decline"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    split = models.ForeignKey(
        BillSplit,
        on_delete=models.CASCADE,
        related_name="history"
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    performed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="split_actions"
    )
    timestamp = models.DateTimeField(default=timezone.now)
    note = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.action} by {self.performed_by} on {self.split}"
