from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from authentication.models import *

# Register your models here.

class LoginUserGroup(ImportExportModelAdmin):
    list_display=['id','user_name','password','organization','is_active','is_admin','is_super_admin','is_logged_in']
admin.site.register(LoginUser,LoginUserGroup)

class RoleUserGroup(ImportExportModelAdmin):
    list_display=['id','name','description','organization','is_active','created_date']
admin.site.register(Role,RoleUserGroup)