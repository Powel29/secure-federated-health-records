from __future__ import annotations

from django.urls import path

from admin_audit import views

app_name = "admin_audit"

urlpatterns = [path("", views.home, name="home")]
