from __future__ import annotations

from django.urls import path

from clinician import views

app_name = "clinician"

urlpatterns = [path("", views.home, name="home")]
