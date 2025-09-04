from django.db.models import Sum, Case, When, DecimalField
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import *

class BillCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = BillCreateSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            bill = serializer.save()
            return Response({"message": "Bill created", "bill_id": str(bill.id), "bill_details":BillCreateSerializer(bill).data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BillListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        bills = (
            Bill.objects.filter(created_by=request.user)
            .select_related("created_by")             # join user in same query
            .prefetch_related("splits__user")         # prefetch splits + users
            .annotate(
                total_paid=Sum(
                    Case(
                        When(splits__status="paid", then="splits__amount"),
                        output_field=DecimalField()
                    )
                ),
                total_pending=Sum(
                    Case(
                        When(splits__status__in=["pending", "approved"], then="splits__amount"),
                        output_field=DecimalField()
                    )
                ),
            )
        )
        serializer = BillSerializer(bills, many=True)
        return Response({
            "message": "All created bills retrieved successfully",
            "data": serializer.data,
        })

class SpecificBillView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, bill_id):
        bill = (
            Bill.objects
            .select_related("created_by")      # fetch bill + creator in same query
            .prefetch_related("splits__user")  # fetch all splits + their users in one query
            .get(id=bill_id)
        )
        return Response({
            "message": "Bill retrieved successfully",
            "data": SingleBillSerializer(bill).data
        })
