"""Root URL routing for the portals."""

from __future__ import annotations

from accounts import views as account_views
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", account_views.home, name="home"),
    path("accounts/", include("accounts.urls")),
    path("patient/", include("patient.urls")),
    path("clinician/", include("clinician.urls")),
    path("oversight/", include("admin_audit.urls")),
    path("django-admin/", admin.site.urls),
]
