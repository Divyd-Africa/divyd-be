from django.contrib import admin
from .models import *
# Register your models here.
admin.site.register(User)
admin.site.register(UserOTP)
admin.site.register(UserBank)
admin.site.register(UserDevice)
admin.site.register(Group)
admin.site.register(Friend)
admin.site.register(GroupMember)