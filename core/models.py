from django.db import models

# Create your models here.
class BaseModel(models.Model):
    created_by = models.CharField(max_length=50, blank=True, null=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_by = models.CharField(max_length=50, blank=True, null=True)
    modified_date = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

class Organization(BaseModel):
    name = models.CharField(max_length=100, blank=False, null=False)
    description = models.CharField(max_length=255, blank=False, null=False)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = 'organization_details'