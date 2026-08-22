from __future__ import annotations

from django.urls import path

from patient import views

app_name = "patient"

urlpatterns = [path("", views.home, name="home")]
