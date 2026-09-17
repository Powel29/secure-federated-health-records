"""Portal-side coordination ledger (ADR-0043).

Three kinds of *display and coordination* data the portals keep in their own
schema. None of it decides access:

- :class:`ConsentRecord` mirrors the request-then-approve flow (ADR-0014) so a
  patient can see what is pending and a clinician can see what was decided.
  The **signed artifacts** it stores -- the clinician's ``ConsentRequest`` and
  the patient's ``ConsentGrant`` -- are public, signed JSON produced by the Key
  Custodian; the grant is *also* submitted to and verified by the facility
  node, which is the only place a grant ever authorises a read (ADR-0031).
  A row here with ``status=granted`` and no grant at the facility grants
  nothing; a forged row cannot pass the facility's signature check.
- :class:`BreakglassCase` records what the clinician portal was told when a
  break-glass opened (correlation id, shares presented, time-box) so the
  countdown and the admin review have something to render. The authoritative
  record of the event is the audit chain, keyed by the same ``correlation_id``.
- :class:`PatientNotification` (P4-10) is what the patient portal surfaces
  when their record was opened under break-glass, a grant was revoked, or a
  request arrived. Each notification is also appended to the audit chain as a
  ``patient.notification`` event; ``audit_seq`` records where.

Nothing here holds key material, plaintext, or a share.
"""

from __future__ import annotations

from django.db import models


class ConsentStatus(models.TextChoices):
    PENDING = "pending", "Awaiting patient signature"
    GRANTED = "granted", "Granted"
    DENIED = "denied", "Denied"
    REVOKED = "revoked", "Revoked"
    EXPIRED = "expired", "Expired"


class ConsentRecord(models.Model):
    request_id = models.UUIDField(primary_key=True)
    patient_id = models.CharField(max_length=128, db_index=True)
    requester_id = models.CharField(max_length=128, db_index=True)
    requester_facility_id = models.CharField(max_length=128, blank=True)
    scope = models.JSONField(default=list)
    purpose = models.TextField()
    requested_at = models.DateTimeField()
    request_expires_at = models.DateTimeField()
    status = models.CharField(
        max_length=16, choices=ConsentStatus.choices, default=ConsentStatus.PENDING
    )
    # Signed public artifacts (never keys): the ConsentRequest as the custodian
    # signed it, and the latest ConsentGrant (granted / denied / revoked).
    request_json = models.JSONField()
    grant_json = models.JSONField(null=True, blank=True)
    grant_expires_at = models.DateTimeField(null=True, blank=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    correlation_id = models.CharField(max_length=128, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-requested_at"]

    def __str__(self) -> str:
        return f"{self.requester_id} -> {self.patient_id} [{self.status}]"

    @property
    def is_actionable(self) -> bool:
        return self.status == ConsentStatus.PENDING

    @property
    def is_live(self) -> bool:
        return self.status == ConsentStatus.GRANTED


class CaseStatus(models.TextChoices):
    OPEN = "open", "Emergency-open"
    EXPIRED = "expired", "Expired · rotated"
    FAILED = "failed", "Failed closed"


class BreakglassCase(models.Model):
    correlation_id = models.CharField(max_length=128, unique=True)
    record_id = models.CharField(max_length=128, db_index=True)
    patient_id = models.CharField(max_length=128, db_index=True)
    clinician_id = models.CharField(max_length=128, db_index=True)
    facility_id = models.CharField(max_length=128)
    reason_code = models.CharField(max_length=64)
    justification = models.TextField(blank=True)
    assertion_id = models.CharField(max_length=64, blank=True)
    status = models.CharField(
        max_length=16, choices=CaseStatus.choices, default=CaseStatus.OPEN
    )
    failure_reason = models.TextField(blank=True)
    shares = models.JSONField(default=list)  # [{holder, x, audit_entry_seq}]
    audit_entry_seq = models.BigIntegerField(null=True, blank=True)
    opened_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.correlation_id} {self.record_id} [{self.status}]"

    @property
    def case_number(self) -> str:
        return f"BG-{self.pk:04d}"


class NotificationKind(models.TextChoices):
    BREAKGLASS = "breakglass", "Break-glass access"
    REVOKED = "revoked", "Grant revoked"
    CONSENT_REQUEST = "consent_request", "Access request received"
    CONSENT_DECISION = "consent_decision", "Consent decision recorded"


class PatientNotification(models.Model):
    patient_id = models.CharField(max_length=128, db_index=True)
    kind = models.CharField(max_length=32, choices=NotificationKind.choices)
    title = models.CharField(max_length=200)
    body = models.TextField(blank=True)
    record_id = models.CharField(max_length=128, blank=True)
    correlation_id = models.CharField(max_length=128, blank=True, db_index=True)
    audit_seq = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.patient_id}: {self.title}"

    @property
    def is_unread(self) -> bool:
        return self.read_at is None
