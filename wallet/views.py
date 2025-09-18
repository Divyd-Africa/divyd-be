import hashlib
import hmac
import json

from django.db import transaction
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
import uuid
from Divyd_be import settings
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

#TODO: create the webhook for confirming transfer and updating user balance
@csrf_exempt
def webhook(request):
    try:
        print("Webhook hit")
        kora_sig = request.headers.get('x-korapay-signature')
        payload = request.body
        event_data = json.loads(payload)
        print(event_data)
        payload_data = json.dumps(event_data['data'], separators=(',',':'))
        print(payload_data)

        computed_sig = hmac.new(
            settings.KORA_SECRET.encode('utf-8'),
            payload_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        if computed_sig != kora_sig:
            return JsonResponse({
                "message": "Invalid signature"
            })
        if event_data.get('event') == 'charge.success':
            data = event_data.get("data",{})
            reference = data.get('reference')
            wallet_id = reference.split('-')[1]
            og_reference = reference.split('-')[0]
            try:
                with transaction.atomic():
                    wallet = Wallet.objects.get(id=wallet_id)
                    actual_amount = data.get('amount') - data.get('fee')
                    wallet.balance += actual_amount
                    wallet.save()
                    Transaction.objects.create(wallet=wallet, amount=actual_amount, reference=og_reference, transaction_type=Transaction.CREDIT,category=Transaction.FUNDING)
                    return JsonResponse({
                        "message":"Transaction saved successfully",
                    })
            except Exception as e:
                print(str(e))
                return JsonResponse({
                    "message": f"Something went wrong, {e} ",
                })
    except Exception as err:
        print(str(err))
        return JsonResponse({"message": str(err)})

def pay_debt(user, amount, bill_id, creator, reference=None, meta=None):
    """
    Pay debt from one wallet to another.
    Idempotent: prevents double charges by reference.
    """
    if reference is None:
        reference = f"{bill_id}-{user.id}-{creator.id}"

    try:
        with transaction.atomic():
            # fetch wallets inside transaction
            debtor_wallet = Wallet.objects.select_for_update().get(user=user)
            creditor_wallet = Wallet.objects.select_for_update().get(user=creator)

            # check idempotency
            if Transaction.objects.filter(reference=reference, transaction_type=Transaction.DEBIT).exists():
                return "already_processed"

            # check balance
            if debtor_wallet.balance < amount:
                return "insufficient"

            # debit debtor
            debtor_wallet.balance -= float(amount)
            debtor_wallet.save()
            Transaction.objects.create(
                wallet=debtor_wallet,
                transaction_type=Transaction.DEBIT,
                category=Transaction.TRANSFER,
                amount=amount,
                reference=reference,
                description=f"Payment for bill {bill_id}",
                meta=meta or {},
            )

            # credit creator
            creditor_wallet.balance += float(amount)
            creditor_wallet.save()
            Transaction.objects.create(
                wallet=creditor_wallet,
                transaction_type=Transaction.CREDIT,
                category=Transaction.FUNDING,
                amount=amount,
                reference=f"{reference}-credit",
                description=f"Payment from {user.username} for bill {bill_id}",
                meta=meta or {},
            )

            return "success"

    except Wallet.DoesNotExist:
        return "User does not have a wallet"
    except Exception as e:
        return str(e)





