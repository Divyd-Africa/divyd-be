from django.core.cache import cache
from Divyd_be import settings
import requests

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



