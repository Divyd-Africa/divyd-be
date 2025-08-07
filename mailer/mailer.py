from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from Divyd_be import settings


def send_otp_mail(name, email,otp):
    try:
        subject = "Your Divyd OTP"
        from_email = settings.DEFAULT_FROM_EMAIL
        to = [email]
        html_content = render_to_string("otp_mail.html", {"name":name, "otp":otp})
        email_message = EmailMultiAlternatives(subject, "", from_email, to)
        email_message.attach_alternative(html_content, "text/html")
        email_message.send(fail_silently=False)
    except Exception as e:
        print(f"failed to send email to {email}. Error:{e}")