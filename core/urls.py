from django.urls import path
from core.views.organization_process import *
urlpatterns = [
    path('add/organization/',OrganizationDetail.as_view()),
    path('role/',RoleManagement.as_view()),
    path('user/',UserManagement.as_view()),
    # path('assign/',AssignRole.as_view()),
    
]