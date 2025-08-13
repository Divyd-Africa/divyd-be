from django.db import models
from user.models import User
# Create your models here.
class Wallet(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    balance = models.FloatField(default=0)

    def __str__(self):
        return f"{self.user.username}'s Wallet"

class Transaction(models.Model):
    CREDIT = 'credit'
    DEBIT = 'debit'
    TRANSACTION_TYPES = [
        (CREDIT, 'Credit'),
        (DEBIT, 'Debit'),
    ]

    FUNDING = 'funding'
    TRANSFER = 'transfer'
    WITHDRAWAL = 'withdrawal'
    REVERSAL = 'reversal'
    CATEGORY_TYPES = [
        (FUNDING, 'Funding'),
        (TRANSFER, 'Transfer'),
        (WITHDRAWAL, 'Withdrawal'),
        (REVERSAL, 'Reversal'),
    ]
    wallet = models.ForeignKey(Wallet, on_delete=models.CASCADE, related_name='transactions')
    transaction_type = models.CharField(max_length=6, choices=TRANSACTION_TYPES)
    category = models.CharField(max_length=20, choices=CATEGORY_TYPES)
    amount = models.FloatField()
    reference = models.CharField(max_length=120,unique=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    meta = models.JSONField(blank=True, null=True)

    def __str__(self):
        return self.reference
