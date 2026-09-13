from __future__ import annotations

from django.urls import path

from admin_audit import views

app_name = "admin_audit"

urlpatterns = [
    path("", views.home, name="home"),
    path("trace/", views.trace, name="trace"),
    path("cases/", views.cases, name="cases"),
    path("federation/", views.federation, name="federation"),
    path("registrations/", views.registrations, name="registrations"),
]
