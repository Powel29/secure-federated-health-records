from __future__ import annotations

from django.urls import path

from clinician import views
from clinician import encounters

app_name = "clinician"

urlpatterns = [
    path("encounter/", encounters.encounter, name="encounter"),
    path("downtime/", encounters.downtime, name="downtime"),
    path("cases/<int:pk>/note/", encounters.note, name="note"),
    path(
        "cases/<int:pk>/federated-search/",
        encounters.federated_search,
        name="federated_search",
    ),
    path("", views.home, name="home"),
    path("identify/", views.identify, name="identify"),
    path("identify/select/", views.select_candidate, name="select_candidate"),
    path("breakglass/", views.breakglass, name="breakglass"),
    path("cases/", views.cases, name="cases"),
    path("profile/", views.profile, name="profile"),
    path("cases/<int:pk>/", views.case_detail, name="case_detail"),
    path("consent/", views.consent_request, name="consent_request"),
    path("consent/<uuid:request_id>/read/", views.consent_read, name="consent_read"),
]
