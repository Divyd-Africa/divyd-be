import uuid
from datetime import timedelta
from dateutil.relativedelta import relativedelta
from django.utils.timezone import now

from user.models import *
from bill.models import *
from notifications.notification import send_fcm_v1_message
from celery import shared_task

from wallet.views import pay_debt
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)

@shared_task
def send_new_bill_alert(creator_id, debtor_id, split_data):
    try:
        creator = User.objects.get(id=creator_id)
        print(creator.username)
        debtor = User.objects.get(id=debtor_id)
        token = UserDevice.objects.get(user=debtor).device_token
    except (User.DoesNotExist, UserDevice.DoesNotExist):
        return None

    title = "New Bill Olowo Eko"
    body = f"{creator.firstName} just added you to a bill with your share as {split_data['amount']}"
    data = split_data

    return send_fcm_v1_message(token, title, body, data)
@shared_task
def send_accepted_bill_alert(creator_id,debtor,bill):
    creator = User.objects.get(id=creator_id)
    token = UserDevice.objects.get(user=creator).device_token
    title = f"Yayyy, {debtor} said YES🤭"
    body = f"{debtor} has accepted the {bill['title']} bill, you will get your money soon"
    data = bill
    send_fcm_v1_message(token,title,body,data)

@shared_task
def send_paid_bill_alert(creator_id,debtor,bill):
    creator = User.objects.get(id=creator_id)
    token = UserDevice.objects.get(user=creator).device_token
    title = f"You just got richer"
    body = f"{debtor} has cleared their part of {bill['title']} bill"
    data = bill
    send_fcm_v1_message(token,title,body,data)


@shared_task
def send_declined_bill_alert(creator_id,debtor,bill):
    creator = User.objects.get(id=creator_id)
    token = UserDevice.objects.get(user=creator).device_token
    title = f"DO NOT PAY FOR {debtor}"
    body = f"{debtor} declined the bill, we recommend you don't pay for {bill['title']}"
    data = bill
    send_fcm_v1_message(token,title,body,data)

@shared_task
def send_success_debit(debtor_id, bill_id):
    debtor = User.objects.get(id=debtor_id)
    token = UserDevice.objects.get(user=debtor).device_token
    bill_raw = Bill.objects.get(id=bill_id)
    bill = build_bill_payload(bill_raw)
    title = f"You just got debited for {bill['title']} subscription"
    body = f"Your subscription for {bill['title']} has been paid. You can go about your day darling."
    data = bill
    send_fcm_v1_message(token,title,body,data)

@shared_task
def send_paid_sub_alert(creator_id,debtor,bill_id):
    creator = User.objects.get(id=creator_id)
    token = UserDevice.objects.get(user=creator).device_token
    title = f"You just got richer"
    bill_raw = Bill.objects.get(id=bill_id)
    bill = build_bill_payload(bill_raw)
    body = f"{debtor} has paid their part of {bill['title']} subscription"
    data = bill
    send_fcm_v1_message(token,title,body,data)

@shared_task
def send_failed_debit(debtor_id, bill_id, body):
    debtor = User.objects.get(id=debtor_id)
    token = UserDevice.objects.get(user=debtor).device_token
    bill_raw = Bill.objects.get(id=bill_id)
    bill = build_bill_payload(bill_raw)
    title = f"Failed payment for {bill['title']} subscription"
    body = body
    data = bill
    send_fcm_v1_message(token,title,body,data)

@shared_task
def send_cancelation_alert(creator_id,debtor,bill_id):
    creator = User.objects.get(id=creator_id)
    token = UserDevice.objects.get(user=creator).device_token
    bill_raw = Bill.objects.get(id=bill_id)
    bill = build_bill_payload(bill_raw)
    title = f"Canceling {bill['title']} for {debtor}"
    data = bill
    body = f"Subscription for {bill['title']} has been cancelled for {debtor} as they have missed 3 cycles"
    send_fcm_v1_message(token,title,body,data)


def build_bill_payload(bill:Bill):
    return {
        "id": bill.id,
        "title": bill.title,
        "created_by": bill.created_by,
    }
@shared_task(bind=True, max_retries=4)
def process_due_recurring_bills(self):
    """
    This task should run once per day (via Celery beat or cronjob).
    It checks all active recurring bills where next_run is due,
    processes them, and then updates their next_run based on frequency.
    """
    logger.info("starting tasks")
    due_bills = (
        RecurringBill.objects
        .filter(is_active=True, next_run__lte=now())
        .select_related("creator", "bill")
        .prefetch_related("recurringbillparticipant_set__user")
    )
    for bill in due_bills:
        logger.info(f"handling recurring bill: {bill.id}")
        participants = bill.recurringbillparticipant_set.all()

        for participant in participants:
            reference = uuid.uuid4()
            if participant.status == "pending":
                # They haven’t accepted yet → increment arrears
                participant.missed_cycles += 1
                participant.save(update_fields=["missed_cycles"])

                # If they hit arrears cap, auto-cancel
                if participant.missed_cycles >= 3:
                    participant.status = "rejected"
                    participant.save(update_fields=["status"])
                    send_cancelation_alert.delay(bill.bill.created_by.id, participant.user.username,bill.bill.id)
                    # TODO: send notification to creator that participant was auto-cancelled
                continue

            if participant.status == "accepted":
                total_due = participant.amount * (1 + participant.missed_cycles)

                result = pay_debt(
                    user=participant.user,
                    amount=total_due,
                    bill_id=bill.id,
                    creator=bill.creator,
                    reference=reference,
                    meta={"recurring": True, "participant_id": participant.id, "arrears": participant.missed_cycles},
                )

                if result == "success":
                    # reset arrears after successful payment
                    participant.missed_cycles = 0
                    participant.save(update_fields=["missed_cycles"])
                    send_paid_sub_alert.delay(bill.bill.created_by.id, participant.user.username,bill.bill.id)
                    send_success_debit.delay(participant.user.id, bill.bill.id, result)
                    # log success here
                    RecurringBillLog.objects.create(
                                        recurring_bill=bill,
                                        user=participant.user,
                                        amount=participant.amount,
                                        reference=f"{reference}-{self.request.id}",
                                        status=RecurringBillLog.SUCCESS,
                                        message="Payment successful",
                                        attempt_number=self.request.retries + 1,
                                    )

                else:
                    # failed payment → increment arrears
                    participant.missed_cycles += 1
                    participant.save(update_fields=["missed_cycles"])
                    send_failed_debit.delay(participant.user.id, bill.bill.id, result)
                    if participant.missed_cycles >= 3:
                        participant.status = "rejected"
                        participant.save(update_fields=["status"])
                        send_cancelation_alert.delay(bill.bill.created_by.id, participant.user.username, bill.bill.id)
                        # TODO: send notification to creator that participant was auto-cancelled
                    # log failure here
                    RecurringBillLog.objects.create(
                                        recurring_bill=bill,
                                        user=participant.user,
                                        amount=participant.amount,
                                        reference=reference,
                                        status=RecurringBillLog.SKIPPED,
                                        message=result,
                                        attempt_number=self.request.retries + 1,
                                    )

            elif participant.status == "rejected":
                # Ignore cancelled participants
                continue

        # After all participants are handled, advance bill
        bill.next_run = calculate_next_run(bill)
        bill.save(update_fields=["next_run"])


def calculate_next_run(bill):
    """Helper to compute the next_run timestamp based on frequency."""
    if bill.frequency == "daily":
        return bill.next_run + timedelta(days=1)
    elif bill.frequency == "weekly":
        return bill.next_run + timedelta(weeks=1)
    elif bill.frequency == "monthly":
        return bill.next_run + relativedelta(months=1)
    return bill.next_run
