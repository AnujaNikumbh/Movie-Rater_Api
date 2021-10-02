from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator, MinLengthValidator

# Create your models here.
class UserReg(AbstractUser):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(max_length=50, unique=True)
    password = models.CharField(max_length=20, validators=[MinLengthValidator(6)])
    httpsconfirm_password = models.CharField(max_length=20, validators=[MinLengthValidator(6)])