"""Patient portal (P4-7, P4-10): access control, history, own records, alerts.

Every page identifies the patient (Django login -> ``Profile.subject_id``) and
renders data; every state change is a POST that goes to the Key Custodian
(which signs as the patient) and to the owning facility (which verifies). The
portal never holds the patient's key and never decides access -- a decrypted
record only ever appears here because the facility's policy engine released
it for this one request (ADR-0014/0016/0043).
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.contrib import messages
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone as dj_tz
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST
from portal_core import notify, policies, services, store_reader
from portal_core.access import role_required
from portal_core.services import ServiceError

from accounts.models import Role
from ledger.models import (
    BreakglassCase,
    CaseStatus,
    ConsentRecord,
    ConsentStatus,
    PatientNotification,
)

GRANT_TTL_DAYS = 5

# Uploaded content types a browser may render inline (review F42).
_INLINE_CONTENT_TYPES = frozenset(
    {"application/pdf", "image/png", "image/jpeg", "text/plain"}
)


def _store(fn: Any, *args: Any, default: Any = None) -> tuple[Any, str | None]:
    """Run a read-only store query; on failure return (default, error)."""
    try:
        return fn(*args), None
    except Exception as exc:  # noqa: BLE001 - display-only, never fatal
        return default, str(exc)


def _refresh_case_status(case: BreakglassCase) -> BreakglassCase:
    if case.status == CaseStatus.OPEN and case.expires_at and case.expires_at <= dj_tz.now():
        case.status = CaseStatus.EXPIRED
        case.save(update_fields=["status"])
    return case


def _open_cases(patient_id: str) -> list[BreakglassCase]:
    return [
        _refresh_case_status(c)
        for c in BreakglassCase.objects.filter(patient_id=patient_id).exclude(
            status=CaseStatus.FAILED
        )
    ]


def _base_ctx(request: Any, screen: str) -> dict[str, Any]:
    subject_id = request.user.profile.subject_id
    unread = PatientNotification.objects.filter(
        patient_id=subject_id, read_at__isnull=True
    ).count()
    open_cases = [c for c in _open_cases(subject_id) if c.status == CaseStatus.OPEN]
    return {
        "crumb_role": "Patient security portal",
        "crumb_screen": screen,
        "subject_id": subject_id,
        "unread_count": unread,
        "active_case": open_cases[0] if open_cases else None,
        "nav": [
            ("patient:home", "Overview"),
            ("patient:access", "Access control & consent"),
            ("patient:records", "Encrypted health records"),
            ("patient:history", "Access history"),
        ],
    }


# --- Page 1: overview ---------------------------------------------------------------


@role_required(Role.PATIENT)
def home(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Overview")
    subject_id = ctx["subject_id"]
    records, store_error = _store(store_reader.records_for_patient, subject_id, default=[])
    pending = ConsentRecord.objects.filter(
        patient_id=subject_id, status=ConsentStatus.PENDING
    )
    live = ConsentRecord.objects.filter(patient_id=subject_id, status=ConsentStatus.GRANTED)
    notifications = PatientNotification.objects.filter(patient_id=subject_id)[:8]
    ctx.update(
        {
            "records": records,
            "store_error": store_error,
            "pending_count": pending.count(),
            "live_count": live.count(),
            "notifications": notifications,
            "cases": _open_cases(subject_id)[:5],
            "enrolled": services_subject_safe(subject_id),
            "requests": request.user.requests.all(),
        }
    )
    return render(request, "patient/home.html", ctx)


def services_subject_safe(subject_id: str) -> dict[str, Any] | None:
    try:
        return services.custodian_subject(subject_id)
    except ServiceError:
        return None


@role_required(Role.PATIENT)
@require_POST
def mark_read(request: Any, pk: int) -> HttpResponse:
    note = get_object_or_404(
        PatientNotification, pk=pk, patient_id=request.user.profile.subject_id
    )
    if note.read_at is None:
        note.read_at = dj_tz.now()
        note.save(update_fields=["read_at"])
    # Only same-host relative targets; anything else goes home (review F42).
    target = request.POST.get("next")
    if target and url_has_allowed_host_and_scheme(
        target, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return redirect(target)
    return redirect("patient:home")


# --- Page 2: access control & consent ------------------------------------------------


@role_required(Role.PATIENT)
def access(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Access control & consent")
    subject_id = ctx["subject_id"]
    now = dj_tz.now()
    rows = ConsentRecord.objects.filter(patient_id=subject_id)
    # Lapse unanswered requests whose window closed; nothing signs, nothing grants.
    rows.filter(status=ConsentStatus.PENDING, request_expires_at__lte=now).update(
        status=ConsentStatus.EXPIRED
    )
    rows.filter(status=ConsentStatus.GRANTED, grant_expires_at__lte=now).update(
        status=ConsentStatus.EXPIRED
    )
    pending = list(rows.filter(status=ConsentStatus.PENDING))
    for row in pending:
        row.requester = services_subject_safe(row.requester_id)
    ctx.update(
        {
            "pending": pending,
            "grants": rows.exclude(status=ConsentStatus.PENDING)[:50],
            "cases": _open_cases(subject_id),
            "enrolled": services_subject_safe(subject_id),
        }
    )
    return render(request, "patient/access.html", ctx)


@role_required(Role.PATIENT)
@require_POST
def decide(request: Any, request_id: str) -> HttpResponse:
    """Approve or deny: the custodian signs as the patient; the facility verifies."""
    subject_id = request.user.profile.subject_id
    row = get_object_or_404(ConsentRecord, request_id=request_id, patient_id=subject_id)
    decision = request.POST.get("decision")
    if row.status != ConsentStatus.PENDING or decision not in ("granted", "denied"):
        messages.error(request, "This request is no longer open for a decision.")
        return redirect("patient:access")
    try:
        signed = services.custodian_decide_consent(
            subject_id, request=row.request_json, status=decision, ttl_days=GRANT_TTL_DAYS
        )
        services.facility_submit_grant(
            row.requester_facility_id or _first_facility(row),
            grant=signed["grant"],
            patient_public_key_pem=signed["patient_public_key_pem"],
        )
    except ServiceError as exc:
        messages.error(request, f"Decision not recorded — {exc.service}: {exc.detail}")
        return redirect("patient:access")
    grant = signed["grant"]
    row.status = ConsentStatus.GRANTED if decision == "granted" else ConsentStatus.DENIED
    row.grant_json = grant
    row.grant_expires_at = _parse_ts(grant["expires_at"])
    row.decided_at = dj_tz.now()
    row.save()
    notify.append_audit(
        event_type=notify.EVENT_CONSENT_DECISION,
        event_data={
            "request_id": str(row.request_id),
            "grant_id": grant["grant_id"],
            "patient_id": subject_id,
            "grantee_id": row.requester_id,
            "status": decision,
            "scope": list(row.scope),
        },
        actor_id=notify.ACTOR_PATIENT_PORTAL,
        correlation_id=row.correlation_id,
    )
    messages.success(
        request,
        f"Signed {decision} for {row.requester_id} — grant {grant['grant_id'][:8]}… "
        f"verified and stored by the facility.",
    )
    return redirect("patient:access")


@role_required(Role.PATIENT)
@require_POST
def revoke(request: Any, request_id: str) -> HttpResponse:
    """Revocation is patient-only and cryptographic: a fresh patient-signed REVOKED grant."""
    subject_id = request.user.profile.subject_id
    row = get_object_or_404(ConsentRecord, request_id=request_id, patient_id=subject_id)
    if row.status != ConsentStatus.GRANTED or not row.grant_json:
        messages.error(request, "Only a live grant can be revoked.")
        return redirect("patient:access")
    try:
        signed = services.custodian_revoke_consent(subject_id, prior_grant=row.grant_json)
        services.facility_submit_grant(
            row.requester_facility_id or _first_facility(row),
            grant=signed["grant"],
            patient_public_key_pem=signed["patient_public_key_pem"],
        )
    except ServiceError as exc:
        messages.error(request, f"Revocation not recorded — {exc.service}: {exc.detail}")
        return redirect("patient:access")
    row.status = ConsentStatus.REVOKED
    row.grant_json = signed["grant"]
    row.decided_at = dj_tz.now()
    row.save()
    notify.append_audit(
        event_type=notify.EVENT_CONSENT_DECISION,
        event_data={
            "request_id": str(row.request_id),
            "grant_id": signed["grant"]["grant_id"],
            "patient_id": subject_id,
            "grantee_id": row.requester_id,
            "status": "revoked",
            "scope": list(row.scope),
        },
        actor_id=notify.ACTOR_PATIENT_PORTAL,
        correlation_id=row.correlation_id,
    )
    notify.notify_revoked(
        patient_id=subject_id,
        grantee_id=row.requester_id,
        scope=list(row.scope),
        correlation_id=row.correlation_id,
    )
    messages.success(request, f"Revoked {row.requester_id}'s grant; the facility now refuses it.")
    return redirect("patient:access")


def _first_facility(row: ConsentRecord) -> str:
    facilities = list(settings.FACILITY_URLS)
    return facilities[0] if facilities else ""


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


# --- Page 3: access history ------------------------------------------------------------


def _describe(entry: dict[str, Any]) -> dict[str, Any]:
    data = entry.get("event_data") or {}
    if isinstance(data, str):
        data = json.loads(data)
    et = entry["event_type"]
    kind = "info"
    if et in store_reader.BREAKGLASS_EVENT_TYPES:
        kind = "breakglass"
    elif et == "access_denied":
        kind = "denial"
    elif et == "access_granted":
        kind = "read"
    elif et in store_reader.LIFECYCLE_EVENT_TYPES:
        kind = "lifecycle"
        if data.get("to_state") == "emergency_open":
            kind = "breakglass"
    elif et == "patient.notification":
        kind = "notice"
    elif et == "consent.decision":
        kind = "consent"
    actor = (
        data.get("requester_id")
        or data.get("clinician_id")
        or data.get("target_actor_id")
        or data.get("grantee_id")
        or entry.get("actor_id")
    )
    detail = ", ".join(
        f"{k}={v}"
        for k, v in data.items()
        if k in ("record_id", "access_via", "denied_by", "reason", "from_state", "to_state", "status", "kind", "reason_code", "record_count")
    )
    return {**entry, "event_data": data, "kind": kind, "actor": actor, "detail": detail}


@role_required(Role.PATIENT)
def history(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Access history")
    subject_id = ctx["subject_id"]
    records, store_error = _store(store_reader.records_for_patient, subject_id, default=[])
    ids = [r["record_id"] for r in records]
    entries, err2 = _store(store_reader.audit_for_patient, subject_id, ids, default=[])
    rows = [_describe(e) for e in entries]
    flt = request.GET.get("type", "all")
    if flt == "breakglass":
        rows = [r for r in rows if r["kind"] == "breakglass"]
    elif flt == "denials":
        rows = [r for r in rows if r["kind"] == "denial"]
    elif flt == "reads":
        rows = [r for r in rows if r["kind"] == "read"]
    ctx.update({"rows": rows, "filter": flt, "store_error": store_error or err2})
    return render(request, "patient/history.html", ctx)


# --- Page 4: encrypted records and the one-request view -----------------------------


@role_required(Role.PATIENT)
def records(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Encrypted health records")
    rows, store_error = _store(store_reader.records_for_patient, ctx["subject_id"], default=[])
    ctx.update(
        {"records": rows, "store_error": store_error, "enrolled": services_subject_safe(ctx["subject_id"])}
    )
    return render(request, "patient/records.html", ctx)


@role_required(Role.PATIENT)
def record_view(request: Any, record_id: str) -> HttpResponse:
    """Decrypt through the owner leaf for this one request; never persisted."""
    ctx = _base_ctx(request, "Encrypted health records")
    subject_id = ctx["subject_id"]
    meta, store_error = _store(store_reader.record_meta, record_id)
    if store_error:
        ctx.update({"record": None, "store_error": store_error})
        return render(request, "patient/record_view.html", ctx, status=503)
    if not meta or meta["patient_id"] != subject_id:
        # Do not reveal whether another patient's record exists.
        raise Http404("record not found")
    ctx["record"] = meta
    ctx["enrolled"] = services_subject_safe(subject_id)
    if request.method != "POST":
        return render(request, "patient/record_view.html", ctx)

    correlation_id = f"owner-read-{uuid4()}"
    try:
        result = services.custodian_read(
            subject_id,
            record_id=record_id,
            facility_id=meta["facility_id"],
            correlation_id=correlation_id,
        )
    except ServiceError as exc:
        ctx.update({"denied": exc.detail, "denied_service": exc.service, "correlation_id": correlation_id})
        return render(request, "patient/record_view.html", ctx, status=403 if exc.is_denial else 503)

    plaintext = base64.b64decode(result["plaintext_b64"])
    content_type = result.get("content_type") or meta["content_type"]
    if request.POST.get("mode") == "raw" or not _renderable(content_type):
        # The content type is the uploader's claim. Only a short list of
        # passive types is shown inline; anything else (HTML, SVG, scripts)
        # downloads, and the browser may not sniff a different type (F42).
        disposition = (
            "inline" if content_type in _INLINE_CONTENT_TYPES else "attachment"
        )
        response = HttpResponse(plaintext, content_type=content_type)
        response["Content-Disposition"] = f'{disposition}; filename="{record_id}"'
        response["X-Content-Type-Options"] = "nosniff"
        response["Cache-Control"] = "no-store"
        return response
    ctx.update(
        {
            "plaintext": _pretty(plaintext, content_type),
            "correlation_id": result.get("correlation_id") or correlation_id,
            "attributes_presented": result.get("attributes_presented", []),
            "access_via": result.get("access_via"),
        }
    )
    response = render(request, "patient/record_view.html", ctx)
    response["Cache-Control"] = "no-store"
    return response


# --- Upload: the patient's own record, sealed by the facility -------------------

MAX_UPLOAD_BYTES = 5 * 1024 * 1024


@role_required(Role.PATIENT)
def upload(request: Any) -> HttpResponse:
    """Hand a file to the key agent, which has the facility encrypt and index it.

    The bytes pass through this request once and are never stored by the
    portal; what lands in the store is AES-256-GCM ciphertext sealed under
    ``OR(chosen clinical policy, owner:<patient_id>)`` (ADR-0016).
    """
    ctx = _base_ctx(request, "Encrypted health records")
    subject_id = ctx["subject_id"]
    enrolled = services_subject_safe(subject_id)
    facilities = list(settings.FACILITY_URLS)
    default_facility = (
        request.user.profile.home_facility_id
        or (enrolled or {}).get("facility_id")
        or (facilities[0] if facilities else "")
    )
    ctx.update(
        {
            "enrolled": enrolled,
            "facilities": facilities,
            "facility_id": default_facility,
            "presets": policies.preset_choices(),
            "preset": "general",
            "search_terms": "",
            "max_mb": MAX_UPLOAD_BYTES // (1024 * 1024),
        }
    )
    if request.method != "POST":
        return render(request, "patient/upload.html", ctx)

    upload_file = request.FILES.get("file")
    preset = request.POST.get("preset", "")
    facility_id = request.POST.get("facility_id", "").strip()
    terms = [t.strip() for t in request.POST.get("search_terms", "").split(",") if t.strip()]
    ctx.update({"preset": preset, "facility_id": facility_id, "search_terms": ", ".join(terms)})

    policy = policies.policy_for(preset)
    if upload_file is None or policy is None or facility_id not in facilities:
        ctx["error"] = "Choose a file, a clinical access policy and a facility."
        return render(request, "patient/upload.html", ctx, status=400)
    if upload_file.size == 0 or upload_file.size > MAX_UPLOAD_BYTES:
        ctx["error"] = f"The file must be between 1 byte and {ctx['max_mb']} MB."
        return render(request, "patient/upload.html", ctx, status=400)

    content = upload_file.read()
    content_type = upload_file.content_type or "application/octet-stream"
    try:
        result = services.custodian_ingest(
            subject_id,
            facility_id=facility_id,
            content=content,
            content_type=content_type,
            clinical_policy=policy,
            search_terms=terms,
        )
    except ServiceError as exc:
        ctx["error"] = f"Not sealed — {exc.service}: {exc.detail}"
        return render(request, "patient/upload.html", ctx, status=403 if exc.is_denial else 503)
    finally:
        del content

    messages.success(
        request,
        f"Sealed {result['record_id']} at {facility_id}: policy {result['policy_id'][:8]}…, "
        f"{result['search_terms_indexed']} search term(s) indexed, share 3 in audit custody. "
        f"Your owner leaf is present — open it under Encrypted health records.",
    )
    return redirect("patient:records")


def _renderable(content_type: str) -> bool:
    return content_type.startswith("text/") or "json" in content_type


def _pretty(plaintext: bytes, content_type: str) -> str:
    text = plaintext.decode("utf-8", errors="replace")
    if "json" in content_type:
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            return text
    return text
