"""Patient notifications (P4-10) and portal-originated audit events.

A notification is two things at once: a row the patient portal surfaces
(``ledger.PatientNotification``) and a ``patient.notification`` entry in the
audit chain, so "the patient was told" is itself tamper-evident. The row is
written first and always; the chain append is attempted immediately after and
its ``seq`` stored on the row. If the audit service is down the row carries
``audit_seq=None`` and the portal shows it as *not yet in the chain* -- a
patient is never left un-notified because the log was unreachable, but the gap
is visible rather than silent.

Event payloads carry identifiers only -- never names, dates of birth, keys,
or plaintext (CONVENTIONS.md §2 rule 3).
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from portal_core import services
from portal_core.services import ServiceError

from ledger.models import NotificationKind, PatientNotification

_logger = logging.getLogger(__name__)

# Mirrors ``audit.events`` (src) -- the portal does not import src/.
EVENT_PATIENT_LOOKUP = "patient.lookup"
EVENT_PATIENT_NOTIFICATION = "patient.notification"
EVENT_CONSENT_DECISION = "consent.decision"

ACTOR_CLINICIAN_PORTAL = "portal:clinician"
ACTOR_PATIENT_PORTAL = "portal:patient"
ACTOR_NOTIFIER = "portal:notifier"


def append_audit(
    *, event_type: str, event_data: dict[str, Any], actor_id: str, correlation_id: str
) -> int | None:
    """Append one event; return its ``seq`` or ``None`` if the chain was unreachable."""
    try:
        entry = services.audit_append(
            event_type=event_type,
            event_data=event_data,
            actor_id=actor_id,
            correlation_id=correlation_id,
        )
    except ServiceError as exc:
        _logger.warning("audit append %s failed: %s", event_type, exc.detail)
        return None
    return int(entry["seq"])


def notify_patient(
    *,
    patient_id: str,
    kind: str,
    title: str,
    body: str = "",
    record_id: str = "",
    correlation_id: str = "",
    actor_id: str = "",
) -> PatientNotification:
    """Create the notification row, then record it in the audit chain."""
    note = PatientNotification.objects.create(
        patient_id=patient_id,
        kind=kind,
        title=title,
        body=body,
        record_id=record_id,
        correlation_id=correlation_id,
    )
    seq = append_audit(
        event_type=EVENT_PATIENT_NOTIFICATION,
        event_data={
            "notification_id": note.pk,
            "kind": kind,
            "patient_id": patient_id,
            "record_id": record_id,
            "actor_id": actor_id,
        },
        actor_id=ACTOR_NOTIFIER,
        correlation_id=correlation_id or f"notify-{note.pk}",
    )
    if seq is not None:
        note.audit_seq = seq
        note.save(update_fields=["audit_seq"])
    return note


def notify_breakglass(
    *,
    patient_id: str,
    record_id: str,
    clinician_id: str,
    facility_id: str,
    correlation_id: str,
    reason_code: str,
) -> PatientNotification:
    from accounts.models import PatientRepresentative
    from django.utils import timezone

    try:
        subject = services.custodian_subject(clinician_id) or {}
        clinician_name = subject.get("display_name") or clinician_id
    except ServiceError:
        clinician_name = clinician_id
    note = notify_patient(
        patient_id=patient_id,
        kind=NotificationKind.BREAKGLASS,
        title="Your record was opened under emergency break-glass",
        body=(
            f"Record {record_id} was opened by {clinician_name} ({clinician_id}) at {facility_id} "
            f"(reason: {reason_code}). The access is time-boxed and fully logged; "
            f"follow the correlation id to the audit evidence."
        ),
        record_id=record_id,
        correlation_id=correlation_id,
        actor_id=clinician_id,
    )
    for representative in PatientRepresentative.objects.filter(
        patient__subject_id=patient_id,
        receive_notifications=True,
        revoked_at__isnull=True,
        expires_at__gt=timezone.now(),
    ):
        notify_patient(
            patient_id=representative.representative_id,
            kind=NotificationKind.BREAKGLASS,
            title="Emergency access notice for a patient you represent",
            body="An emergency access event has been recorded. Contact the care team through the approved channel for details.",
            correlation_id=correlation_id,
            actor_id=clinician_id,
        )
    return note


def notify_revoked(
    *, patient_id: str, grantee_id: str, scope: list[str], correlation_id: str
) -> PatientNotification:
    return notify_patient(
        patient_id=patient_id,
        kind=NotificationKind.REVOKED,
        title=f"Access for {grantee_id} was revoked",
        body=(
            f"Your signed revocation covers {', '.join(scope)}. The facility now "
            f"refuses reads under the earlier grant."
        ),
        record_id=scope[0] if scope else "",
        correlation_id=correlation_id,
        actor_id=patient_id,
    )


def notify_consent_request(
    *, patient_id: str, requester_id: str, scope: list[str], correlation_id: str
) -> PatientNotification:
    return notify_patient(
        patient_id=patient_id,
        kind=NotificationKind.CONSENT_REQUEST,
        title=f"{requester_id} is asking for access",
        body=f"Requested scope: {', '.join(scope)}. Approve or deny under Access.",
        record_id=scope[0] if scope else "",
        correlation_id=correlation_id,
        actor_id=requester_id,
    )


def query_hash(*parts: str) -> str:
    """Hash of a lookup query so the chain records *that* a search happened, not *what* was typed."""
    return hashlib.sha256(
        "\x1f".join(p.strip().lower() for p in parts).encode()
    ).hexdigest()
