from django.core.cache import cache
from Divyd_be import settings
import requests
import uuid
BASE_URL = 'https://api.korapay.com/merchant/api/v1'
secret = settings.KORA_SECRET
public = settings.KORA_PUBLIC
encryption = settings.KORA_ENCRYPTION
def get_all_banks():
    cache_key = 'banks_list'
    banks = cache.get(cache_key)
    if banks is None:
        response = requests.get(f"{BASE_URL}/misc/banks?countryCode=NG",
                                headers={'Authorization':f"Bearer {public}", 'Content-Type':'application/json'})
        banks = response.json()
        cache.set(cache_key, banks, 60*60*5)

    return banks

def verify_bank_details(bank_code, account_number):
    response = requests.post(f"{BASE_URL}/misc/banks/resolve", headers={
        'Content-Type': 'application/json'
    },json={
        "bank":bank_code,
        "account":account_number,
    })
    return response.json()

def create_virtual_account(user):
    payload = {
        'account_name':user.firstName + ' ' + user.lastName,
        # 'account_reference':f'{user.username}-{user.id}',
        'account_reference':"1234rfrfv",
        'permanent':True,
        'bank_code':"000",
        'customer':{
            "name":user.username,
            "email":user.email,
        },
        'kyc':{
            'bvn':'00000000000'
        }
    }
    response = requests.post(f"{BASE_URL}/virtual-bank-account", json=payload, headers={
        'Content-Type': 'application/json',
        'Authorization':f"Bearer {secret}"
    })
    return response.json()

def generate_temp_account(amount, user):
    payload = {
        "reference":f"{uuid.uuid4().hex}-{user.wallet.id}",
        "amount":amount,
        "currency":"NGN",
        "customer":{
            "email":user.email
        },
        "account_name":f"{user.firstName} {user.lastName}'s Divyd",
        "merchant_bears_cost":False,
        "metadata":{
            "user_id":user.id,
            "wallet_id":user.wallet.id
        },
        "notification_url":"https://2b1c0f3f3840.ngrok-free.app/api/v1/wallet/webhook"
    }
    response = requests.post(f"{BASE_URL}/charges/bank-transfer", json=payload, headers={
        'Content-Type': 'application/json',
        'Authorization':f"Bearer {secret}"
    })
    return response.json()
##TODO
def transfer(amount, account, bank_code):
    pass

def encrypt_payload():
    pass

