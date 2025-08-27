from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import *

# Create your views here.
def equal_split(amount,total_users):
    return amount/total_users

def split_by_percent(amount,percent):
    actual = (percent / 100) * amount
    return actual

class CreateBillView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        body = request.data
        user = request.user
        serializer = BillSerializer(data=body)
        if serializer.is_valid():
            bill = serializer.save(created_by=user)
            total = bill.total_amount
            if body.get("participants"):
                type = body["type"]
                if type == "equal":
                    share = equal_split(total,len(body["participants"]))
                elif type == "percentage":
                    pass








