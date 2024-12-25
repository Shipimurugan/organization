from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from core.models import *
# from authentication.models import *
# Register your models here.

class OrganizationUserGroup(ImportExportModelAdmin):
    list_display=['id','name','description','is_active','created_date']
admin.site.register(Organization,OrganizationUserGroup)


