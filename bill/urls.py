from django.urls import path
from .views import *
urlpatterns = [
    path('create', BillCreateView.as_view(), name='create'),
    path('mine',BillListView.as_view(), name='mine'),
    path("mine/<str:bill_id>",SpecificBillView.as_view(),name="specific-mine")
]