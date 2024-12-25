from django.db import models
from core.models import BaseModel, Organization

# Create your models here.

class Role(BaseModel):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=255, blank=False, null=False)
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,null=True,blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'role'

class LoginUser(BaseModel):
    user_name = models.CharField(max_length=50, blank=True, null=True,unique=True)
    password = models.CharField(max_length=230)
    email_address = models.CharField(max_length=100, blank=True, null=True)
    phone_number = models.CharField(max_length=32, blank=True, null=True)
    is_admin = models.BooleanField(default=False)
    is_super_admin = models.BooleanField(default=False)
    is_logged_in = models.BooleanField(default=False)
    organization = models.ForeignKey(Organization,on_delete=models.CASCADE,null=True,blank=True)
    role = models.ForeignKey(Role,on_delete=models.CASCADE,null=True,blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'login_user'