from django.contrib.auth.base_user import AbstractBaseUser
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser):
    firstName = models.CharField(verbose_name='First Name', max_length=255)
    lastName = models.CharField(verbose_name='Last Name', max_length=255)
    email = models.EmailField(verbose_name='Email', max_length=255, unique=True)
    phoneNumber = models.CharField(verbose_name='Phone Number', max_length=255)
    username = models.CharField(verbose_name='Username', max_length=255, unique=True)
    pin = models.CharField(verbose_name='PIN', default=None, blank=True, null=True)
    is_email_verified = models.BooleanField(verbose_name='Email Verified', default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    date_joined = models.DateTimeField(verbose_name='Date Joined', auto_now_add=True, null=True)

    objects = CustomUserManager()
    USERNAME_FIELD = ('username')
    REQUIRED_FIELDS = ['firstName', 'lastName', 'email']

    def __str__(self):
        return self.username

    def get_full_name(self):
        return self.firstName + ' ' + self.lastName
    def get_short_name(self):
        return self.firstName
    def has_perm(self, perm, obj=None):
        return self.is_superuser or super().has_perm(perm, obj)
    def has_module_perms(self, app_label):
        return self.is_superuser

class UserOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.IntegerField(verbose_name='OTP', null=True, blank=True)
    otp_created_at = models.DateTimeField(verbose_name='OTP Created', auto_now_add=True)

    def __str__(self):
        return self.user.username


class UserBank(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bank_code = models.CharField(verbose_name='Bank Code', max_length=10)
    bank_name = models.CharField(verbose_name='Bank Name', max_length=255)
    account_number = models.CharField(verbose_name='Account Number', max_length=11)

    def __str__(self):
        return self.user.username