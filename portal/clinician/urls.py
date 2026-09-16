from __future__ import annotations

from django.urls import path

from clinician import views

app_name = "clinician"

urlpatterns = [
    path("", views.home, name="home"),
    path("identify/", views.identify, name="identify"),
    path("identify/select/", views.select_candidate, name="select_candidate"),
    path("breakglass/", views.breakglass, name="breakglass"),
    path("cases/", views.cases, name="cases"),
    path("cases/<int:pk>/", views.case_detail, name="case_detail"),
    path("consent/", views.consent_request, name="consent_request"),
    path("consent/<uuid:request_id>/read/", views.consent_read, name="consent_read"),
]
