from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from helpers import kora_functions
from .models import *
from .serializers import *
# Create your views here.
def createWallet(user):
    Wallet.objects.create(user=user)

class WalletListView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        user = request.user
        try:
            wallet = Wallet.objects.get(user=user)
            return Response({
                "message": "Wallet retrieved created",
                "wallet": WalletSerializer(wallet).data,
            })
        except Wallet.DoesNotExist:
            return Response({
                "message": "Wallet does not exist",
            },status=status.HTTP_404_NOT_FOUND)

class FundWalletView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        user = request.user
        body = request.data
        try:
            amount = float(body.get('amount'))
        except (TypeError, ValueError):
            return Response({
                "message": "Amount is required as a number",
            })
        if amount <= 100:
            return Response({
                "message": "Amount must be greater than 100",
            },status=status.HTTP_400_BAD_REQUEST)
        try:
            Wallet.objects.get(user=user)
            response = kora_functions.generate_temp_account(amount,user)
            return Response({
                "message":"Virtual account generated successfully",
                "response":response
            })
        except Wallet.DoesNotExist:
            return Response({
                "message":"User Wallet not activated"
            },status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({
                "message":f"Something went wrong, {e} ",
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)