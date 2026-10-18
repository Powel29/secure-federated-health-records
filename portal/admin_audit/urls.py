from __future__ import annotations

from django.urls import path

from admin_audit import views
from admin_audit import clinical

app_name = "admin_audit"

urlpatterns = [
    path("cases/<int:pk>/review/", clinical.review, name="review"),
    path("downtime/", clinical.downtime, name="downtime"),
    path("representatives/", clinical.representatives, name="representatives"),
    path("", views.home, name="home"),
    path("trace/", views.trace, name="trace"),
    path("cases/", views.cases, name="cases"),
    path("federation/", views.federation, name="federation"),
    path("registrations/", views.registrations, name="registrations"),
]
