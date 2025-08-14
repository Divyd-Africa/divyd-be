from django.urls import path

from wallet.views import WalletListView, FundWalletView

urlpatterns = [
    path('',WalletListView.as_view(),name='wallet-list'),
    path('fund',FundWalletView.as_view(),name='wallet-fund'),
]