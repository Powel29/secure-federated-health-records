"""Thin HTTP client for talking to the standalone Audit Service (P4-2, C14).

No cryptography here (CONVENTIONS.md §2 rule 10) -- every hash and signature
is computed by the Audit Service itself; this module only shapes HTTP calls
to it, so a caller (a facility node, the expiry timer, a seed script) never
needs to hold the audit signing key to get something logged.

Closes the seam ``lifecycle.expiry.EmergencyExpiryManager`` documents as
deferred to Phase 4:

    "Audit chain wiring (P3-3/P3-4) is deferred to Phase 4 API integration
    (P4-2); pass an ``audit_logger`` callback then. With ``audit_logger=None``,
    expiry events do NOT enter the hash chain -- documented limitation
    (ADR-0035)."

:func:`make_lifecycle_audit_logger` is that callback.
"""

from __future__ import annotations

from typing import Any, Callable

import httpx

DEFAULT_TIMEOUT_SECONDS = 5.0


def _tls_verify() -> bool:
    """Allow the P4-6 local capture harness to use self-signed TLS."""
    import os
    return os.environ.get("TLS_VERIFY", "true").lower() not in {"0", "false", "no"}


class AuditServiceError(RuntimeError):
    """The Audit Service could not be reached, or refused the request."""


def append_entry(
    audit_service_url: str,
    *,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """POST one entry to the Audit Service's ``/entries`` endpoint.

    Args:
        audit_service_url: Base URL of the standalone Audit Service, e.g.
            ``"http://audit:8020"`` -- from the config allowlist
            (CONVENTIONS.md §2 rule 8), never from request-supplied data.
        event_type: e.g. ``"lifecycle_transition"``.
        event_data: Metadata only -- never key material (CONVENTIONS.md §2
            rule 3); this function does not enforce that, only forwards it.
        actor_id: The party responsible for the logged event.
        correlation_id: Groups this entry with the rest of its logical flow.
        timeout: HTTP request timeout in seconds.

    Returns:
        The newly persisted ``AuditEntry`` as a plain dict (already
        base64/ISO-serialized JSON from the service response).

    Raises:
        AuditServiceError: The request failed or the service returned a
            non-2xx response.

    Security property:
        Fails closed by propagating the error rather than swallowing it --
        a caller that needs this entry logged (e.g. the expiry timer, whose
        transition should be tamper-evident) finds out immediately if it
        was not.
    """
    try:
        resp = httpx.post(
            f"{audit_service_url}/entries",
            json={
                "event_type": event_type,
                "event_data": event_data,
                "actor_id": actor_id,
                "correlation_id": correlation_id,
            },
            timeout=timeout,
            verify=_tls_verify(),
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise AuditServiceError(
            f"audit service append failed for correlation_id={correlation_id!r}: {exc}"
        ) from exc
    return resp.json()["entry"]


def make_lifecycle_audit_logger(
    audit_service_url: str, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> Callable[[dict[str, Any]], None]:
    """Build the ``audit_logger`` callback ``EmergencyExpiryManager`` expects.

    Args:
        audit_service_url: Base URL of the standalone Audit Service.
        timeout: Per-request HTTP timeout in seconds.

    Returns:
        A ``Callable[[dict[str, Any]], None]`` suitable for
        ``EmergencyExpiryManager(..., audit_logger=...)``. Each call logs one
        ``lifecycle_transition`` entry, using the transition's own
        ``actor_id`` (the timer service identity, not the facility) and its
        ``correlation_id`` -- both already present in the metadata dict
        ``lifecycle.expiry._transition_metadata`` builds.
    """

    def _log(entry: dict[str, Any]) -> None:
        append_entry(
            audit_service_url,
            event_type="lifecycle_transition",
            event_data=entry,
            actor_id=entry["actor_id"],
            correlation_id=entry["correlation_id"],
            timeout=timeout,
        )

    return _log
