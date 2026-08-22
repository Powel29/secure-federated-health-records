"""Registration + login routing (ADR-0021, request-then-issue).

Registration creates a login and a PENDING RegistrationRequest. It NEVER issues a
credential -- that is the authority's job (P2-2), stubbed here. So a freshly
registered account holds no working attribute and can decrypt nothing.
"""

from __future__ import annotations

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.shortcuts import redirect, render

from accounts.models import Profile, RegistrationRequest, RequestStatus, Role


@login_required
def home(request):
    """Send a logged-in user to their portal by role."""
    role = getattr(getattr(request.user, "profile", None), "role", None)
    if role == Role.PATIENT:
        return redirect("patient:home")
    if role == Role.CLINICIAN:
        return redirect("clinician:home")
    if role == Role.ADMIN:
        return redirect("admin_audit:home")
    return render(request, "home.html", {})


def _create_login(username: str, password: str, role: str, subject_id: str) -> User:
    """Create a User + Profile + PENDING request atomically. Issues nothing."""
    with transaction.atomic():
        user = User.objects.create_user(username=username, password=password)
        Profile.objects.create(user=user, role=role, subject_id=subject_id)
        RegistrationRequest.objects.create(
            user=user,
            role=role,
            subject_id=subject_id,
            status=RequestStatus.PENDING,
        )
    return user


def register_patient(request):
    """Patient self-registration: creates a login + a request for an owner key."""
    if request.method == "POST":
        data = request.POST
        try:
            user = _create_login(
                data["username"],
                data["password"],
                Role.PATIENT,
                data["patient_id"],
            )
        except (IntegrityError, KeyError):
            return render(
                request,
                "accounts/register_patient.html",
                {"error": "Username or patient id already taken, or fields missing."},
            )
        RegistrationRequest.objects.filter(user=user).update(
            requested_attributes=f"owner:{data['patient_id']}"
        )
        login(request, user)
        return redirect("patient:home")
    return render(request, "accounts/register_patient.html", {})


def register_clinician(request):
    """Clinician self-registration: creates a login + a request for role/specialty.

    The requested role/specialty is recorded for an authority to verify and
    issue. Nothing is granted here -- the account holds no attribute until an
    authority issues one (P2-2).
    """
    if request.method == "POST":
        data = request.POST
        try:
            user = _create_login(
                data["username"],
                data["password"],
                Role.CLINICIAN,
                data["clinician_id"],
            )
        except (IntegrityError, KeyError):
            return render(
                request,
                "accounts/register_clinician.html",
                {"error": "Username or clinician id already taken, or fields missing."},
            )
        RegistrationRequest.objects.filter(user=user).update(
            requested_attributes=data.get("requested_attributes", ""),
            license_info=data.get("license_info", ""),
        )
        login(request, user)
        return redirect("clinician:home")
    return render(request, "accounts/register_clinician.html", {})
