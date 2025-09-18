from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid


class Bill(models.Model):
    SPLIT_TYPE_CHOICES = (
        ("equal", "Equal"),
        ("custom_amount", "Custom Amount"),
        ("custom_percent", "Custom Percent"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    split_type = models.CharField(max_length=20, choices=SPLIT_TYPE_CHOICES, default="equal")
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Bill {self.id}"

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
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default="created")
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

class RecurringBill(models.Model):
    bill = models.ForeignKey(Bill, on_delete=models.CASCADE, related_name="recurring_bills", null=True, blank=True)
    creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="recurring_bills")
    # participants = models.ManyToManyField(settings.AUTH_USER_MODEL, related_name="recurring_debts")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    frequency = models.CharField(max_length=20, choices=[
        ("monthly", "Monthly"),
        ("weekly", "Weekly"),
        ("daily", "Daily"),
        ("yearly","Yearly"),
    ])
    next_run=models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.bill.title} by {self.creator}"

class RecurringBillParticipant(models.Model):
    recurring_bill = models.ForeignKey(RecurringBill, on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=[
        ("pending", "Pending"),
        ("accepted", "Accepted"),
        ("rejected", "Rejected"),
    ], default="pending")
    joined_at = models.DateTimeField(auto_now_add=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    missed_cycles = models.PositiveIntegerField(
        default=0,
        help_text="How many billing cycles this user has missed"
    )

    # optional: if you want to mark *why* they were cancelled
    cancellation_reason = models.CharField(
        max_length=255,
        blank=True,
        null=True
    )

    def total_due(self):
        """
        Total amount currently owed by this participant,
        including arrears (missed cycles + current cycle).
        """
        return self.amount * (1 + self.missed_cycles)

    def __str__(self):
        return f"{self.user.username} in {self.recurring_bill} ({self.status})"


class RecurringBillLog(models.Model):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"   # e.g. when user had insufficient funds, and you skip retry until next cycle

    STATUS_CHOICES = [
        (SUCCESS, "Success"),
        (FAILED, "Failed"),
        (SKIPPED, "Skipped"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recurring_bill = models.ForeignKey(
        "RecurringBill", on_delete=models.CASCADE, related_name="logs"
    )
    user = models.ForeignKey(
        "user.User", on_delete=models.CASCADE, related_name="recurring_bill_logs"
    )

    amount = models.DecimalField(max_digits=12, decimal_places=2)
    reference = models.CharField(max_length=120, unique=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    attempt_number = models.PositiveIntegerField(default=1)

    # light but useful metadata
    message = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["recurring_bill", "user", "status"]),
            models.Index(fields=["created_at"]),
        ]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.recurring_bill.bill.title} - {self.user.username} - {self.status}"


