from django.urls import path

from . import views

urlpatterns = [
    path("", views.callback, name="auth0"),
    path("login", views.login, name="auth0_login"),
    path("logout", views.logout, name="auth0_logout"),
    path("callback", views.callback, name="auth0_callback"),
]
