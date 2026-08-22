from __future__ import annotations

from django.contrib.auth import views as auth_views
from django.urls import path

from accounts import views

app_name = "accounts"

urlpatterns = [
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="registration/login.html"),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("register/patient/", views.register_patient, name="register_patient"),
    path("register/clinician/", views.register_clinician, name="register_clinician"),
]
