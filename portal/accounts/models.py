"""Portal identity models (ADR-0021).

These live in the `portal` schema and carry *identity only* -- who a login is and
what enrollment they have requested. They hold **no keys and grant no access**: a
Profile with role CLINICIAN does not make anyone a physician; only an
authority-issued credential (P2-2) does. That is the ADR-0021 invariant.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class Role(models.TextChoices):
    PATIENT = "patient", "Patient"
    CLINICIAN = "clinician", "Clinician"
    ADMIN = "admin", "Admin / audit"


class Profile(models.Model):
    """Links a Django login to its domain identifier and role (name tag only)."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile"
    )
    role = models.CharField(max_length=16, choices=Role.choices)
    # The domain id used across the crypto system, e.g. "pat-101" or "doc-201".
    subject_id = models.CharField(max_length=128, unique=True)
    home_facility_id = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.subject_id} ({self.role})"


class RequestStatus(models.TextChoices):
    PENDING = "pending", "Pending authority review"
    APPROVED = "approved", "Approved (awaiting issuance)"
    ISSUED = "issued", "Credential issued"
    DENIED = "denied", "Denied"


class RegistrationRequest(models.Model):
    """A self-service enrollment request. Never issues a credential itself.

    The request is the *self-service* half; an authority performs the *issue*
    half (P2-2). Until then a request sits PENDING and its subject holds no
    working attribute -- so a self-registered account grants nothing.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="requests"
    )
    role = models.CharField(max_length=16, choices=Role.choices)
    subject_id = models.CharField(max_length=128)
    # What the requester is asking to be certified for, e.g.
    # "role:physician, specialty:cardiology" or "owner:pat-101". Free text at the
    # portal; the authority decides what to actually issue.
    requested_attributes = models.TextField(blank=True)
    # Doctor-only: license / proof the authority verifies before issuing.
    license_info = models.TextField(blank=True)
    status = models.CharField(
        max_length=16, choices=RequestStatus.choices, default=RequestStatus.PENDING
    )
    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.subject_id} [{self.role}] -> {self.status}"
