import decimal

from django.db.models import Sum, Case, When, DecimalField
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import *
from wallet.views import *

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
        try:
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
        except Bill.DoesNotExist:
            return Response({
                "message": "Bill not found",
            },status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                "message": str(e),
            },status=status.HTTP_400_BAD_REQUEST)
class SplitsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        splits = BillSplit.objects.filter(user=request.user).select_related("user","bill")
        serializer = BillSplitSerializer(splits, many=True)
        return Response({
            "message": "All splits retrieved successfully",
            "data": serializer.data,
        },status=status.HTTP_200_OK)


class AcceptSplitView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, split_id):
        try:
            split = BillSplit.objects.get(id=split_id)
        except BillSplit.DoesNotExist:
            return Response({
                "message": "Bill not found",
            },status=status.HTTP_404_NOT_FOUND)
        if split.status != "pending":
            return Response({
                "message": "Bill is no longer pending",
                "data":BillSplitSerializer(split).data
            },status=status.HTTP_400_BAD_REQUEST)
        split.status = "approved"
        split.save()
        try:
            cleared = pay_debt(request.user,split.amount,split.bill.id,split.bill.created_by)
            if cleared == "success":
                split.status = "paid"
                split.save()
                return Response({
                    "message":"Bill Accepted and cleared",
                    "data":BillSplitSerializer(split).data
                },status=status.HTTP_200_OK)
            else:
                return Response({
                    "message":"Bill Accepted but could not be cleared",
                    "reason":cleared,
                    "data":BillSplitSerializer(split).data
                },status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                "message": str(e),
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PaySplitView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, split_id):
        try:
            split = BillSplit.objects.get(id=split_id)
        except BillSplit.DoesNotExist:
            return Response({
                "message": "Bill not found",
            },status=status.HTTP_404_NOT_FOUND)
        if split.status != "declined" and split.status != "paid":
            cleared = pay_debt(request.user,split.amount,split.bill.id,split.bill.created_by)
            if cleared == "success":
                split.status = "paid"
                split.save()
                return Response({
                    "message":"Bill has been cleared",
                    "data":BillSplitSerializer(split).data
                },status=status.HTTP_200_OK)
            else:
                return Response({
                    "message":"Failed to clear bill",
                    "reason":cleared,
                    "data":BillSplitSerializer(split).data
                },status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({
                "message":"Bill has either been paid or was declined",
                "data":BillSplitSerializer(split).data
            })

class DeclineSplitView(APIView):
    permission_classes = [IsAuthenticated]
    def put(self, request, split_id):
        try:
            split = BillSplit.objects.get(id=split_id)
        except BillSplit.DoesNotExist:
            return Response({
                "message": "Bill not found",
            },status=status.HTTP_404_NOT_FOUND)
        if split.status != "pending":
            return Response({
                "message": "Bill is no longer pending",
                "data":BillSplitSerializer(split).data
            },status=status.HTTP_400_BAD_REQUEST)
        else:
            with transaction.atomic():
                split.status = "declined"
                split.save()
                creator_split = BillSplit.objects.get(bill=split.bill, is_creator=True)
                creator_split.amount += split.amount
                creator_split.save()
                return Response({
                    "message":"Bill has been declined",
                },status=status.HTTP_200_OK)







