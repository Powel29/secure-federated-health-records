"""Typed audit events for access denials and federation actions (P3-13,
ARCHITECTURE.md §5 step 1 "log-before-release" family; admin/audit portal
read surface, WORKFLOW.md P4-9).

``audit.chain.append_entry`` accepts any ``event_type`` string and an
arbitrary ``event_data`` dict -- correct by design (ADR-0034), since it lets
every module log without a contract change. That flexibility means nothing
fixes the *shape* of a denial or federation event across callers, and nothing
stops an event from accidentally carrying more than an identifier or a hash.
This module is that fixed shape for exactly two families of event this task
covers:

- **Access denials** -- a policy, consent, credential, or revocation-
  authorization check refused a request (``policy.exceptions.PolicyDeniedError``,
  ``consent.exceptions.ConsentDeniedError``/``ConsentRevokedError``,
  ``authority.exceptions.UnauthorizedAttributeError``,
  ``records.exceptions.UnauthorizedRevocationError``, and similar). Every one
  of those modules deliberately does not audit-log itself -- see
  ``breakglass/gate.py``'s and ``records/revocation.py``'s module docstrings,
  "the caller persists + audit-logs" -- so a caller that catches one of these
  exceptions logs it here with a fixed, minimal shape.
- **Federation actions** -- cross-facility discovery
  (``federation.discovery.find_record_ids_by_patient``) and the PRE re-wrap
  step of cross-facility break-glass (``breakglass.gate.open_emergency_access``
  step 4). Both modules return plain data/results and, per the same
  "caller persists + audit-logs" convention, do not call into ``audit``
  themselves.

Per CLAUDE.md's one-owner-per-module rule, this module does not reach into
``policy``, ``consent``, ``authority``, ``records``, ``breakglass``, or
``federation`` to insert calls at their raise sites or return points -- that
wiring belongs to whichever orchestration layer calls them (the Phase 4 API
services, P4-1/P4-2), matching the pattern those modules already document.
What this module guarantees is that when a caller does call one of these
functions, the resulting event carries identifiers and hashes only, never a
key, a share, a DEK, or plaintext (CONVENTIONS.md §2 rule 3) -- see
``docs/adr/0038-denial-and-federation-audit-events.md``.
"""

from __future__ import annotations

import datetime
from typing import Any

import psycopg
from contracts import AuditEntry
from crypto_core import sha256_digest
from cryptography.hazmat.primitives.asymmetric import ec

from audit.chain import append_entry

EVENT_ACCESS_DENIED = "access_denied"
EVENT_FEDERATION_DISCOVERY = "federation.discovery"
EVENT_FEDERATION_REWRAP = "federation.rewrap"

# Suggested, non-exhaustive values for ``log_access_denied``'s ``denied_by`` --
# free text is still accepted (a future denial source needs no contract
# change), but callers that match one of these should use the constant so the
# admin portal's denial view (P4-9) can filter reliably.
DENIED_BY_POLICY = "policy"
DENIED_BY_CONSENT = "consent"
DENIED_BY_CREDENTIAL = "credential_authority"
DENIED_BY_REVOCATION_AUTHZ = "revocation_authorization"


def log_access_denied(
    conn: psycopg.Connection,
    *,
    record_id: str,
    requester_id: str,
    denied_by: str,
    reason: str,
    actor_id: str,
    correlation_id: str,
    signing_key: ec.EllipticCurvePrivateKey,
    timestamp: datetime.datetime | None = None,
) -> AuditEntry:
    """Log a denied access attempt.

    Args:
        record_id: The record the request was refused against.
        requester_id: The party whose request was denied.
        denied_by: Which control refused it -- one of the ``DENIED_BY_*``
            constants, or a caller-defined short label for a control this
            module does not yet name.
        reason: A short, human-readable reason. Callers pass the message of
            the caught ``*DeniedError``/``*UnauthorizedError`` -- every such
            message in this codebase already names only identifiers and a
            plain-language cause (see e.g. ``PolicyDeniedError``,
            ``UnauthorizedRevocationError``), never key material, so no
            further redaction happens here.
        actor_id: The party responsible for logging this event (normally the
            service that ran the check, not the denied requester).
        correlation_id: Ties this denial to the rest of its request flow
            (ADR-0017).
        signing_key: The audit service's ECDSA-P256 private key.
        timestamp: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        The newly persisted, signed :class:`~contracts.AuditEntry`.

    Raises:
        EmptyChainError: No genesis entry exists yet.

    Security property:
        ``event_data`` holds only identifiers and a reason string -- never an
        attribute key, a DEK, a share, or plaintext. ``append_entry``
        JSON-canonicalises ``event_data`` before hashing (ADR-0034); passing
        raw ``bytes`` (e.g. a key by mistake) raises ``TypeError`` there
        before anything is persisted (see
        ``tests/security/test_phase3_denial_federation_audit_security.py``).
    """
    event_data: dict[str, Any] = {
        "record_id": record_id,
        "requester_id": requester_id,
        "denied_by": denied_by,
        "reason": reason,
    }
    return append_entry(
        conn,
        event_type=EVENT_ACCESS_DENIED,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        signing_key=signing_key,
        timestamp=timestamp,
    )


def log_federation_discovery(
    conn: psycopg.Connection,
    *,
    patient_id: str,
    requester_id: str,
    record_ids: list[str],
    actor_id: str,
    correlation_id: str,
    signing_key: ec.EllipticCurvePrivateKey,
    timestamp: datetime.datetime | None = None,
) -> AuditEntry:
    """Log a federated discovery lookup (``federation.discovery``, C13).

    Args:
        patient_id: The patient the caller searched for. Never stored raw --
            only its SHA-256 hash goes into ``event_data`` (see Security
            property), matching this codebase's existing convention of
            keeping patient identity out of audit metadata
            (``records.revocation.RevocationResult.audit_payload`` likewise
            omits ``patient_id``, carrying only ``record_id``).
        requester_id: The facility or clinician that ran the lookup.
        record_ids: The record identifiers the lookup returned (may be
            empty -- an empty result is still logged, matching ARCHITECTURE
            §5 step 0's "the lookup itself is a ... audit event whether or
            not a match is selected").
        actor_id: The party responsible for logging this event.
        correlation_id: Ties this lookup to the rest of its request flow.
        signing_key: The audit service's ECDSA-P256 private key.
        timestamp: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        The newly persisted, signed :class:`~contracts.AuditEntry`.

    Security property:
        ``patient_id`` never appears in ``event_data`` -- only
        ``sha256_digest(patient_id)`` does, hex-encoded so it survives JSON
        canonicalisation as a plain string. A reader of the chain can
        correlate repeated lookups for the same patient without the chain
        itself becoming a store of patient identities (ADR-0011: no PII in
        the crypto store).
    """
    event_data: dict[str, Any] = {
        "patient_id_hash": sha256_digest(patient_id.encode("utf-8")).hex(),
        "requester_id": requester_id,
        "record_count": len(record_ids),
        "record_ids": list(record_ids),
    }
    return append_entry(
        conn,
        event_type=EVENT_FEDERATION_DISCOVERY,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        signing_key=signing_key,
        timestamp=timestamp,
    )


def log_federation_rewrap(
    conn: psycopg.Connection,
    *,
    record_id: str,
    source_facility_id: str,
    target_actor_id: str,
    actor_id: str,
    correlation_id: str,
    signing_key: ec.EllipticCurvePrivateKey,
    timestamp: datetime.datetime | None = None,
) -> AuditEntry:
    """Log a cross-facility PRE re-wrap (``breakglass.gate`` step 4, C3).

    Args:
        record_id: The record whose DEK was re-wrapped.
        source_facility_id: The record's home facility.
        target_actor_id: The out-of-network clinician the DEK was re-wrapped
            for.
        actor_id: The party responsible for logging this event.
        correlation_id: Ties this re-wrap to the rest of the break-glass
            flow it belongs to.
        signing_key: The audit service's ECDSA-P256 private key.
        timestamp: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        The newly persisted, signed :class:`~contracts.AuditEntry`.

    Security property:
        ``event_data`` names only the record and the two parties involved --
        never the emergency key, the recovered DEK, the PRE delivery key, or
        ``EmergencyUnlockResult.rewrapped_dek``. A caller wiring this up
        after :func:`breakglass.gate.open_emergency_access` passes identifiers
        it already holds; nothing here accepts key material even by an
        optional parameter, so there is no field to misuse.
    """
    event_data: dict[str, Any] = {
        "record_id": record_id,
        "source_facility_id": source_facility_id,
        "target_actor_id": target_actor_id,
    }
    return append_entry(
        conn,
        event_type=EVENT_FEDERATION_REWRAP,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        signing_key=signing_key,
        timestamp=timestamp,
    )
