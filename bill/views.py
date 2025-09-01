from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .serializers import BillCreateSerializer

class BillCreateView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = BillCreateSerializer(data=request.data, context={"request": request})
        if serializer.is_valid():
            bill = serializer.save()
            return Response({"message": "Bill created", "bill_id": str(bill.id)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
