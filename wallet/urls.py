from django.urls import path

from wallet.views import *

urlpatterns = [
    path('',WalletListView.as_view(),name='wallet-list'),
    path('fund',FundWalletView.as_view(),name='wallet-fund'),
    path('webhook', webhook, name='webhook'),
    path('withdraw',WithdrawWalletView.as_view(),name='withdraw'),
    path('check-fee',CalculateFee.as_view(),name='check-fee'),
]