"""HTTP clients for the federation services the portals call (ADR-0043).

The portals never import ``src/`` and never touch a key. Every action that
needs one goes to the Key Custodian, which signs or performs the call on the
authenticated subject's behalf; everything else (submitting a signed grant,
discovery, emergency search, chain reads, appending portal-originated audit
events) goes straight to the owning service. All URLs come from Django
settings (config allowlist, CONVENTIONS.md §2 rule 8).

Fail closed: a timeout, connection error, or non-2xx raises
:class:`ServiceError` with the upstream ``detail`` so a page can show the
*specific* reason. No caller ever treats a failure as an empty success.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from django.conf import settings

_logger = logging.getLogger(__name__)


class ServiceError(Exception):
    """A federation service refused or could not be reached."""

    def __init__(self, service: str, status: int | None, detail: str) -> None:
        self.service = service
        self.status = status
        self.detail = detail
        super().__init__(f"{service}: {detail}")

    @property
    def is_denial(self) -> bool:
        return self.status in (400, 403, 404)

    @property
    def is_unavailable(self) -> bool:
        return self.status is None or self.status in (502, 503, 504)


@dataclass(frozen=True)
class ServiceStatus:
    name: str
    url: str
    ok: bool
    detail: str


def _client() -> httpx.Client:
    return httpx.Client(timeout=settings.SERVICE_TIMEOUT_SECONDS)


def _detail(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:500]
    if isinstance(body, dict):
        return str(body.get("detail", body))
    return str(body)


def _request(service: str, method: str, url: str, **kwargs: Any) -> Any:
    try:
        with _client() as http:
            resp = http.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        _logger.warning("%s unreachable at %s: %s", service, url, exc)
        raise ServiceError(service, None, f"service unreachable ({exc})") from exc
    if resp.status_code >= 400:
        raise ServiceError(service, resp.status_code, _detail(resp))
    if resp.status_code == 204 or not resp.content:
        return None
    return resp.json()


# --- Key Custodian ------------------------------------------------------------


def custodian_subject(subject_id: str) -> dict[str, Any] | None:
    """Public identity of a subject, or ``None`` when the custodian holds nothing."""
    try:
        return _request(
            "custodian", "GET", f"{settings.CUSTODIAN_URL}/subjects/{subject_id}"
        )
    except ServiceError as exc:
        if exc.status == 404:
            return None
        raise


def custodian_sign_consent_request(
    clinician_id: str, *, patient_id: str, scope: list[str], purpose: str, ttl_days: int
) -> dict[str, Any]:
    return _request(
        "custodian",
        "POST",
        f"{settings.CUSTODIAN_URL}/subjects/{clinician_id}/consent/request",
        json={
            "patient_id": patient_id,
            "scope": scope,
            "purpose": purpose,
            "ttl_days": ttl_days,
        },
    )["request"]


def custodian_decide_consent(
    patient_id: str, *, request: dict[str, Any], status: str, ttl_days: int
) -> dict[str, Any]:
    """Returns ``{"grant": ..., "patient_certificate_pem": ...}``."""
    return _request(
        "custodian",
        "POST",
        f"{settings.CUSTODIAN_URL}/subjects/{patient_id}/consent/decide",
        json={"request": request, "status": status, "ttl_days": ttl_days},
    )


def custodian_revoke_consent(
    patient_id: str, *, prior_grant: dict[str, Any]
) -> dict[str, Any]:
    return _request(
        "custodian",
        "POST",
        f"{settings.CUSTODIAN_URL}/subjects/{patient_id}/consent/revoke",
        json={"prior_grant": prior_grant},
    )


def custodian_read(
    subject_id: str,
    *,
    record_id: str,
    facility_id: str,
    correlation_id: str,
    grant: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "record_id": record_id,
        "facility_id": facility_id,
        "correlation_id": correlation_id,
    }
    if grant is not None:
        body["grant"] = grant
    return _request(
        "custodian",
        "POST",
        f"{settings.CUSTODIAN_URL}/subjects/{subject_id}/read",
        json=body,
    )


def custodian_breakglass(
    clinician_id: str,
    *,
    patient_id: str,
    record_id: str,
    reason_code: str,
    correlation_id: str,
    facility_id: str | None = None,
    emergency_duration_seconds: float | None = None,
    justification: str = "",
    sensitive_justification: str = "",
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "patient_id": patient_id,
        "record_id": record_id,
        "reason_code": reason_code,
        "correlation_id": correlation_id,
        "emergency_duration_seconds": emergency_duration_seconds,
        "justification": justification,
        "sensitive_justification": sensitive_justification,
        "assertion_ttl_seconds": settings.ASSERTION_TTL_SECONDS,
    }
    if facility_id:
        body["facility_id"] = facility_id
    return _request(
        "custodian",
        "POST",
        f"{settings.CUSTODIAN_URL}/subjects/{clinician_id}/breakglass",
        json=body,
    )


def custodian_ingest(
    patient_id: str,
    *,
    facility_id: str,
    content: bytes,
    content_type: str,
    clinical_policy: dict[str, Any],
    search_terms: list[str],
    clinical: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Upload a record of the patient's own; the custodian seals it at the facility."""
    import base64

    return _request(
        "custodian",
        "POST",
        f"{settings.CUSTODIAN_URL}/subjects/{patient_id}/records",
        json={
            "facility_id": facility_id,
            "content_b64": base64.b64encode(content).decode("ascii"),
            "content_type": content_type,
            "clinical_policy": clinical_policy,
            "search_terms": search_terms,
            "clinical": clinical or {},
        },
    )


# --- Facility nodes (no keys in these bodies) ----------------------------------


def _facility_url(facility_id: str) -> str:
    url = settings.FACILITY_URLS.get(facility_id)
    if not url:
        raise ServiceError(
            "facility", 400, f"facility {facility_id!r} is not configured"
        )
    return url


def facility_submit_grant(
    facility_id: str, *, grant: dict[str, Any], patient_certificate_pem: str
) -> dict[str, Any]:
    """Hand a patient-signed grant to the facility, which verifies and stores it."""
    return _request(
        "facility",
        "POST",
        f"{_facility_url(facility_id)}/consent/grants",
        json={"grant": grant, "patient_certificate_pem": patient_certificate_pem},
    )


def facility_discover(facility_id: str, patient_id: str) -> list[str]:
    """Federated discovery (C13); the facility logs ``federation.discovery``."""
    data = _request(
        "facility",
        "GET",
        f"{_facility_url(facility_id)}/patients/{patient_id}/records",
    )
    return list(data["record_ids"])


def facility_emergency_search(
    facility_id: str,
    record_id: str,
    search_term: str,
    requester_id: str,
    correlation_id: str,
) -> list[str]:
    data = _request(
        "facility",
        "POST",
        f"{_facility_url(facility_id)}/records/{record_id}/emergency-search",
        # The facility audits every emergency search with its requester (F8),
        # under the break-glass case's correlation id so it joins that flow.
        json={
            "search_term": search_term,
            "requester_id": requester_id,
            "correlation_id": correlation_id,
        },
    )
    return list(data["record_ids"])


# --- Audit Service -------------------------------------------------------------


def audit_append(
    *, event_type: str, event_data: dict[str, Any], actor_id: str, correlation_id: str
) -> dict[str, Any]:
    """Append a portal-originated event; the audit service signs it."""
    return _request(
        "audit",
        "POST",
        f"{settings.AUDIT_SERVICE_URL}/entries",
        json={
            "event_type": event_type,
            "event_data": event_data,
            "actor_id": actor_id,
            "correlation_id": correlation_id,
        },
    )["entry"]


def audit_verify() -> dict[str, Any]:
    return _request("audit", "GET", f"{settings.AUDIT_SERVICE_URL}/chain/verify")


def audit_head() -> dict[str, Any] | None:
    return _request("audit", "GET", f"{settings.AUDIT_SERVICE_URL}/chain/head")["head"]


# --- Health ----------------------------------------------------------------------


def federation_status() -> list[ServiceStatus]:
    """Health of every configured process, for the admin portal."""
    targets: list[tuple[str, str]] = []
    targets += [(k, v) for k, v in settings.AUTHORITY_URLS.items()]
    targets.append(("audit", settings.AUDIT_SERVICE_URL))
    targets += [(k, v) for k, v in settings.FACILITY_URLS.items()]
    targets.append(("custodian", settings.CUSTODIAN_URL))
    out: list[ServiceStatus] = []
    for name, url in targets:
        try:
            body = _request(name, "GET", f"{url}/health")
            detail = ", ".join(f"{k}={v}" for k, v in (body or {}).items())
            out.append(ServiceStatus(name, url, True, detail))
        except ServiceError as exc:
            out.append(ServiceStatus(name, url, False, exc.detail))
    return out
