from django.urls import path
from .views import *
urlpatterns = [
    path('create', BillCreateView.as_view(), name='create'),
    path('mine',BillListView.as_view(), name='mine'),
    path("mine/<str:bill_id>",SpecificBillView.as_view(),name="specific-mine"),
    path('splits',SplitsView.as_view(),name="splits"),
    path('splits/<str:split_id>/accept',AcceptSplitView.as_view(),name="accept-splits"),
    path('splits/<str:split_id>/settle',PaySplitView.as_view(),name="settle-splits"),
    path('splits/<str:split_id>/decline',DeclineSplitView.as_view(),name="decline-splits"),
    path('create/recurring',CreateRecurringBillView.as_view(),name="create-recurring"),
    path('recurring',GetAllRecurringBillsView.as_view(),name="get-all-recurring"),
    path('accept/recurring/<str:bill_id>',AcceptRecurringBillView.as_view(),name="accept-recurring"),
    path('reject/recurring/<str:bill_id>',DeclineRecurringBillView.as_view(),name="reject-recurring"),
    path('cancel/recurring/<str:bill_id>',CreateRecurringBillView.as_view(),name="cancel-recurring"),
]