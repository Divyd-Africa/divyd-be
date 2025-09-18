import os
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Divyd_be.settings")

app = Celery('Divyd_be')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()