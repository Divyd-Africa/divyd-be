# from django.contrib import admin
# from .models import *
# # Register your models here.
# admin.site.register(Wallet)
# admin.site.register(Transaction)

from django.contrib import admin
from .models import Wallet, Transaction

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('id', 'wallet', 'category', 'amount', 'created_at')
    list_filter = ('category', 'created_at')
    search_fields = ('wallet__user__username',)
    ordering = ('-created_at',)

admin.site.register(Wallet)
