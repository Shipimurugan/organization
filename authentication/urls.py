from django.urls import path
from authentication.views.login_process import *

urlpatterns = [
    path('add/user/',LoginUsersView.as_view()),
    path('login/',LoginAuthenticationView.as_view()),
    path('logout/',LogoutView.as_view()),
]