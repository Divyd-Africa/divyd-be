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
from helpers import kora_functions, encryption_helper
from user.models import UserBank
from .models import *
from .serializers import *
from .tasks import *
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
            wallet = Wallet.objects.get(user=user)
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

class WithdrawWalletView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self,request):
        body = request.data
        user = request.user
        try:
            amount = float(body.get('amount'))
            pin = body.get('pin')
            bank_code = body.get('bank_code')
            account = body.get('account')
            if not amount or not pin or not bank_code or not account:
                return Response({
                    "message": "Amount, pin and bank details are required",
                }, status=status.HTTP_400_BAD_REQUEST)
            if encryption_helper.verify_hash(str(pin),user.pin):
                wallet = Wallet.objects.get(user=user)
                exhausted = check_three(wallet,"withdraw")
                if exhausted:
                    deduct_amount = amount + 100
                else:
                    deduct_amount = amount
                if deduct_amount <= wallet.balance:
                    print(deduct_amount)
                    valid_account = kora_functions.verify_bank_details(bank_code,account)
                    if valid_account["status"]:
                        response = kora_functions.transfer(amount,account,bank_code,(user.firstName +" "+ user.lastName), user.email,wallet.id)
                        if response["status"]:
                            return Response({
                                "message": f"Transfer initiated successfully",
                                "response":response
                            },status=status.HTTP_200_OK)
                        else:
                            return Response({
                                "message":"Transfer failed",
                                "reason":response["message"]
                            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    else:
                        return Response({
                            "message":"Invalid bank details",
                        },status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({
                        "message":"Insufficient funds",
                    },status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({
                    "message":"Incorrect Pin",
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                "message":f"Something went wrong, {e} ",

            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class CalculateFee(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        params = request.query_params

        amount = params.get('amount')
        action = params.get('action')

        # Validate required params
        if not amount or not action:
            return Response({
                "message": "Both 'amount' and 'action' are required parameters."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate amount type
        try:
            amount = float(amount)
        except ValueError:
            return Response({
                "message": "Amount must be a valid number."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate action choice
        if action not in ['fund', 'withdraw']:
            return Response({
                "message": "Action must be either 'fund' or 'withdraw'."
            }, status=status.HTTP_400_BAD_REQUEST)

        wallet = Wallet.objects.get(user=request.user)
        exhausted = check_three(wallet, action)

        if exhausted and action == 'fund':
            fee = determine_fee(amount)
            return Response({
                "message": f"You have exceeded your free {action} limit for today. "
                           f"A fee of ₦{fee} will be deducted from the {action} amount.",
                "show": True
            })
        elif exhausted and action == 'withdraw':
            fee = 100
            return Response({
                "message": f"You have exceeded your free {action} limit for today. "
                           f"A fee of ₦{fee} will be deducted.",
                "show": True
            })
        return Response({"show": False})
def determine_fee(amount):
    if amount < 5000:
        return 100
    elif amount >=5000:
        return (0.02 * amount)

def check_three(wallet,action):
    today = timezone.now().date()
    if action == "fund":
        transaction_count = Transaction.objects.filter(wallet=wallet, category=Transaction.FUNDING,
                                                       created_at__date=today).count()
    elif action == "withdraw":
        transaction_count = Transaction.objects.filter(wallet=wallet, category=Transaction.WITHDRAWAL,
                                                       created_at__date=today).count()

    if transaction_count >= 3:
        return True
    else:
        return False

@csrf_exempt
def webhook(request):
    try:
        print("Webhook hit")
        kora_sig = request.headers.get('x-korapay-signature')
        payload = request.body
        event_data = json.loads(payload)
        payload_data = json.dumps(event_data['data'], separators=(',',':'))

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
                wallet = Wallet.objects.get(id=wallet_id)
                exists = Transaction.objects.filter(wallet=wallet, reference=og_reference).exists()
                if exists:
                    return JsonResponse({
                        "message": "Transaction already exists",
                    })
                else:
                    with transaction.atomic():
                        wallet = Wallet.objects.get(id=wallet_id)
                        bear_cost = check_three(wallet,"fund")
                        if bear_cost:
                            actual_amount = data.get('amount') - determine_fee(data.get('amount'))
                        else:
                            actual_amount = data.get('amount')
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
        elif event_data.get('event') == 'transfer.success':
            data = event_data.get("data", {})
            reference = data.get('reference')
            wallet_id = reference.split('-')[1]
            og_reference = reference.split('-')[0]
            try:
                wallet = Wallet.objects.get(id=wallet_id)
                exists = Transaction.objects.filter(wallet=wallet, reference=og_reference).exists()
                if exists:
                    return JsonResponse({
                        "message": "Transaction already exists",
                    })
                else:
                    with transaction.atomic():
                        exhausted = check_three(wallet,"withdraw")
                        if exhausted:
                            actual_amount = data.get('amount') + 100
                        else:
                            actual_amount = data.get('amount')
                        wallet.balance -= actual_amount
                        wallet.save()
                        Transaction.objects.create(wallet=wallet, amount=actual_amount, reference=og_reference,
                                                   transaction_type=Transaction.DEBIT, category=Transaction.WITHDRAWAL)
                        send_transfer_success(wallet.user_id,data.get('amount'))
                        return JsonResponse({
                            "message": "Transaction saved successfully",
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





