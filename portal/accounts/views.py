"""Registration + login routing (ADR-0021, request-then-issue).

Registration creates a login and a PENDING RegistrationRequest. It NEVER issues a
credential -- that is the authority's job (P2-2), stubbed here. So a freshly
registered account holds no working attribute and can decrypt nothing.

It does not bind an identity either (review F17): the requested ``patient_id``
or ``clinician_id`` is recorded on the request only, so the first person to
type ``doc-201`` into a form does not become that clinician. The ``Profile``
that ties a login to a subject belongs to issuance, which is not wired yet
(``portal_core.stubs.issue_credential`` raises NotWiredYet): until it is, a
self-registered login stays on the pending page, and only seeded accounts
(``deploy/seed_portal.py``) reach a portal.
"""

from __future__ import annotations

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.shortcuts import redirect, render
from portal_core.access import is_issued

from accounts.models import (
    Profile,
    RegistrationRequest,
    RequestStatus,
    Role,
)


@login_required
def home(request):
    """Send a logged-in user to their portal by role."""
    profile = getattr(request.user, "profile", None)
    role = getattr(profile, "role", None)
    if profile is not None and not is_issued(request.user):
        return render(request, "home.html", {"pending": True})
    if role == Role.PATIENT:
        return redirect("patient:home")
    if role == Role.CLINICIAN:
        return redirect("clinician:home")
    if role == Role.ADMIN or request.user.is_superuser:
        return redirect("admin_audit:home")
    pending = RegistrationRequest.objects.filter(
        user=request.user, status=RequestStatus.PENDING
    ).exists()
    return render(request, "home.html", {"pending": pending})


def _create_login(username: str, password: str, role: str, subject_id: str) -> User:
    """Create a User + PENDING request atomically. Binds and issues nothing.

    ``subject_id`` is only what the person *asks* to be; no ``Profile`` is
    made here (review F17). A request for an identity that already has a
    portal account is refused outright.
    """
    if Profile.objects.filter(subject_id=subject_id).exists():
        raise IntegrityError(f"subject {subject_id!r} already has an account")
    with transaction.atomic():
        user = User.objects.create_user(username=username, password=password)
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
        # No PatientDirectory row here (review F17): the directory maps a
        # name and date of birth to a subject id for emergency lookup
        # (ADR-0033), so an unverified sign-up must not write it. The
        # issuing administrator adds it with the identity.
        login(request, user)
        return redirect("home")
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
        return redirect("home")
    return render(request, "accounts/register_clinician.html", {})
