from user.models import *
from bill.models import *
from notifications.notification import send_fcm_v1_message
from celery import shared_task

@shared_task
def send_transfer_success(user_id, amount):
    user = User.objects.get(id=user_id)
    token = UserDevice.objects.get(user=user).device_token
    title = f"Transaction Successful"
    body = f"Your withdrawal of ₦{amount} was successful, you will get your money soon."
    send_fcm_v1_message(token, title, body)