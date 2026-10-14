from __future__ import annotations

from django.urls import path

from patient import views

app_name = "patient"

urlpatterns = [
    path("", views.home, name="home"),
    path("access/", views.access, name="access"),
    path("access/<uuid:request_id>/decide/", views.decide, name="decide"),
    path("access/<uuid:request_id>/revoke/", views.revoke, name="revoke"),
    path("history/", views.history, name="history"),
    path("profile/", views.profile, name="profile"),
    path("records/", views.records, name="records"),
    path("records/upload/", views.upload, name="upload"),
    path("records/<str:record_id>/", views.record_view, name="record_view"),
    path("notifications/<int:pk>/read/", views.mark_read, name="mark_read"),
]
