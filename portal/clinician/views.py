"""Clinician portal (P4-8, P4-8a): identify, request consent, break-glass, search.

The portal holds no keys. Signing (consent requests, the ``EmergencyAssertion``)
and every key-bearing call happen in the Key Custodian on the authenticated
clinician's behalf; the facility's threshold gate and policy engine decide.
Denied actions render the specific upstream reason (ADR-0043).

Emergency identification (P4-8a, ADR-0033): a name + date-of-birth search over
the portal's ``PatientDirectory``. Ambiguous matches are all shown and never
auto-selected; every lookup -- hit, miss, or selection -- is a ``patient.lookup``
audit event, and if that event cannot be written the candidates are not shown.
"""

from __future__ import annotations

import base64
import json
from datetime import date
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone as dj_tz
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST
from portal_core import notify, services, store_reader
from portal_core.access import role_required
from portal_core.services import ServiceError

from accounts.models import PatientDirectory, Role
from ledger.models import (
    BreakglassCase,
    CaseStatus,
    ConsentRecord,
    ConsentStatus,
)

REASON_CODES = [
    ("cardiac_arrest", "CARDIAC-ARREST — cardiac arrest in progress"),
    ("respiratory_failure", "RESP-FAILURE — acute respiratory failure"),
    ("unconscious_patient", "UNCONSCIOUS — unresponsive on arrival"),
    ("major_trauma", "TRAUMA — major trauma admission"),
    ("stroke", "STROKE — suspected acute stroke"),
    ("severe_allergic_reaction", "ANAPHYLAXIS — severe allergic reaction"),
    ("unknown_medication_history", "MED-HISTORY — unknown medication history"),
    ("other_life_threatening", "OTHER — other life-threatening condition"),
]
REQUEST_TTL_DAYS = 7
_DISCOVERY_SESSION_KEY = "clinician.discovery"


def _subject(subject_id: str) -> dict[str, Any] | None:
    try:
        return services.custodian_subject(subject_id)
    except ServiceError:
        return None


def _refresh(case: BreakglassCase) -> BreakglassCase:
    if case.status == CaseStatus.OPEN and case.expires_at and case.expires_at <= dj_tz.now():
        case.status = CaseStatus.EXPIRED
        case.save(update_fields=["status"])
    return case


def _base_ctx(request: Any, screen: str) -> dict[str, Any]:
    profile = request.user.profile
    subject = _subject(profile.subject_id)
    facility_id = (subject or {}).get("facility_id") or profile.home_facility_id
    open_cases = [
        _refresh(c)
        for c in BreakglassCase.objects.filter(
            clinician_id=profile.subject_id, status=CaseStatus.OPEN
        )
    ]
    open_cases = [c for c in open_cases if c.status == CaseStatus.OPEN]
    return {
        "crumb_role": "Clinician portal",
        "crumb_screen": screen,
        "subject_id": profile.subject_id,
        "subject": subject,
        "facility_id": facility_id,
        "active_case": open_cases[0] if open_cases else None,
        "nav": [
            ("clinician:home", "Overview"),
            ("clinician:identify", "Identify patient"),
            ("clinician:breakglass", "Emergency break-glass"),
            ("clinician:consent_request", "Request consent"),
            ("clinician:cases", "Emergency sessions"),
        ],
    }


# --- Overview ------------------------------------------------------------------------


@role_required(Role.CLINICIAN)
def home(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Overview")
    me = ctx["subject_id"]
    ctx.update(
        {
            "requests": request.user.requests.all(),
            "consents": ConsentRecord.objects.filter(requester_id=me)[:10],
            "cases": [_refresh(c) for c in BreakglassCase.objects.filter(clinician_id=me)[:10]],
        }
    )
    return render(request, "clinician/home.html", ctx)


# --- P4-8a: identify by name + DOB ---------------------------------------------------


@role_required(Role.CLINICIAN)
def identify(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Identify patient")
    ctx.update({"candidates": None, "next": request.GET.get("next", "breakglass")})
    if request.method != "POST":
        return render(request, "clinician/identify.html", ctx)

    family = request.POST.get("family_name", "").strip()
    given = request.POST.get("given_name", "").strip()
    dob_raw = request.POST.get("date_of_birth", "").strip()
    ctx.update({"family_name": family, "given_name": given, "date_of_birth": dob_raw})
    ctx["next"] = request.POST.get("next", "breakglass")
    try:
        dob = date.fromisoformat(dob_raw)
    except ValueError:
        ctx["error"] = "Date of birth must be YYYY-MM-DD."
        return render(request, "clinician/identify.html", ctx, status=400)
    if not family:
        ctx["error"] = "Family name is required."
        return render(request, "clinician/identify.html", ctx, status=400)

    qs = PatientDirectory.objects.filter(family_name__iexact=family, date_of_birth=dob)
    if given:
        qs = qs.filter(given_name__istartswith=given)
    candidates = list(qs.order_by("given_name", "subject_id"))

    # Log before showing: a lookup that cannot be recorded is not served.
    correlation_id = f"lookup-{uuid4()}"
    seq = notify.append_audit(
        event_type=notify.EVENT_PATIENT_LOOKUP,
        event_data={
            "clinician_id": ctx["subject_id"],
            "facility_id": ctx["facility_id"],
            "query_hash": notify.query_hash(family, given, dob_raw),
            "candidate_count": len(candidates),
            "candidate_ids": [c.subject_id for c in candidates],
            "selected_patient_id": None,
        },
        actor_id=notify.ACTOR_CLINICIAN_PORTAL,
        correlation_id=correlation_id,
    )
    if seq is None:
        ctx["error"] = (
            "The audit service did not record this lookup, so its results are "
            "withheld (every identification must be in the chain — ADR-0033)."
        )
        return render(request, "clinician/identify.html", ctx, status=503)
    request.session["clinician.lookup"] = {
        "correlation_id": correlation_id,
        "candidate_ids": [c.subject_id for c in candidates],
    }
    ctx.update({"candidates": candidates, "lookup_seq": seq, "correlation_id": correlation_id})
    return render(request, "clinician/identify.html", ctx)


@role_required(Role.CLINICIAN)
@require_POST
def select_candidate(request: Any) -> HttpResponse:
    """The clinician picked one candidate; log the selection, carry the id forward."""
    ctx = _base_ctx(request, "Identify patient")
    lookup = request.session.get("clinician.lookup") or {}
    patient_id = request.POST.get("patient_id", "")
    if patient_id not in lookup.get("candidate_ids", []):
        messages.error(request, "Select a candidate from the current search results.")
        return redirect("clinician:identify")
    correlation_id = lookup["correlation_id"]
    seq = notify.append_audit(
        event_type=notify.EVENT_PATIENT_LOOKUP,
        event_data={
            "clinician_id": ctx["subject_id"],
            "facility_id": ctx["facility_id"],
            "candidate_count": len(lookup["candidate_ids"]),
            "candidate_ids": lookup["candidate_ids"],
            "selected_patient_id": patient_id,
        },
        actor_id=notify.ACTOR_CLINICIAN_PORTAL,
        correlation_id=correlation_id,
    )
    if seq is None:
        messages.error(request, "The audit service did not record the selection; nothing carried forward.")
        return redirect("clinician:identify")
    request.session["clinician.identified"] = {
        "patient_id": patient_id,
        "correlation_id": correlation_id,
    }
    target = "clinician:consent_request" if request.POST.get("next") == "consent" else "clinician:breakglass"
    return redirect(f"{_url(target)}?patient_id={patient_id}")


def _url(name: str) -> str:
    from django.urls import reverse

    return reverse(name)


# --- Break-glass ----------------------------------------------------------------------


def _identified(request: Any, patient_id: str) -> dict[str, Any]:
    """Prefer the correlation id of the lookup that produced this patient_id."""
    ident = request.session.get("clinician.identified") or {}
    if ident.get("patient_id") == patient_id:
        return ident
    return {"patient_id": patient_id, "correlation_id": f"bg-{uuid4()}"}


@role_required(Role.CLINICIAN)
def breakglass(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Emergency break-glass")
    patient_id = (request.POST.get("patient_id") or request.GET.get("patient_id") or "").strip()
    directory = PatientDirectory.objects.filter(subject_id=patient_id).first() if patient_id else None
    discovery = (request.session.get(_DISCOVERY_SESSION_KEY) or {}).get(patient_id)
    ctx.update(
        {
            "patient_id": patient_id,
            "directory": directory,
            "reason_codes": REASON_CODES,
            "discovered": discovery,
            "duration": int(settings.EMERGENCY_DURATION_SECONDS),
            "assertion_ttl": 120,
        }
    )
    if request.method != "POST":
        return render(request, "clinician/breakglass.html", ctx)

    action = request.POST.get("action")
    if not patient_id:
        ctx["error"] = "Identify the patient first — an assertion is bound to a patient_id."
        return render(request, "clinician/breakglass.html", ctx, status=400)

    if action == "discover":
        try:
            ids = services.facility_discover(ctx["facility_id"], patient_id)
        except ServiceError as exc:
            ctx["error"] = f"Discovery refused — {exc.service}: {exc.detail}"
            return render(request, "clinician/breakglass.html", ctx, status=502)
        found = []
        for rid in ids:
            meta = None
            try:
                meta = store_reader.record_meta(rid)
            except Exception:  # noqa: BLE001 - metadata is decoration only
                meta = None
            found.append(meta or {"record_id": rid, "facility_id": "?", "content_type": "?"})
        session = request.session.get(_DISCOVERY_SESSION_KEY) or {}
        session[patient_id] = found
        request.session[_DISCOVERY_SESSION_KEY] = session
        ctx["discovered"] = found
        return render(request, "clinician/breakglass.html", ctx)

    # action == "declare"
    record_id = request.POST.get("record_id", "").strip()
    reason_code = request.POST.get("reason_code", "")
    justification = request.POST.get("justification", "").strip()
    ctx.update({"reason_code": reason_code, "justification": justification, "record_id": record_id})
    if not record_id or reason_code not in dict(REASON_CODES):
        ctx["error"] = "Choose a discovered record and a reason code."
        return render(request, "clinician/breakglass.html", ctx, status=400)

    ident = _identified(request, patient_id)
    correlation_id = ident["correlation_id"]
    try:
        result = services.custodian_breakglass(
            ctx["subject_id"],
            patient_id=patient_id,
            record_id=record_id,
            reason_code=reason_code,
            correlation_id=correlation_id,
            facility_id=ctx["facility_id"],
            emergency_duration_seconds=settings.EMERGENCY_DURATION_SECONDS,
        )
    except ServiceError as exc:
        case = BreakglassCase.objects.create(
            correlation_id=f"{correlation_id}#{uuid4().hex[:6]}",
            record_id=record_id,
            patient_id=patient_id,
            clinician_id=ctx["subject_id"],
            facility_id=ctx["facility_id"] or "",
            reason_code=reason_code,
            justification=justification,
            status=CaseStatus.FAILED,
            failure_reason=f"{exc.service}: {exc.detail}",
        )
        ctx.update({"error": f"Break-glass refused — {exc.service}: {exc.detail}", "failed_case": case})
        return render(
            request, "clinician/breakglass.html", ctx, status=403 if exc.is_denial else 503
        )

    case = BreakglassCase.objects.create(
        correlation_id=result["correlation_id"],
        record_id=record_id,
        patient_id=patient_id,
        clinician_id=ctx["subject_id"],
        facility_id=result["facility_id"],
        reason_code=reason_code,
        justification=justification,
        assertion_id=result["assertion_id"],
        status=CaseStatus.OPEN,
        shares=result["shares_presented"],
        audit_entry_seq=next(
            (s.get("audit_entry_seq") for s in result["shares_presented"] if s.get("audit_entry_seq")),
            None,
        ),
        opened_at=parse_datetime(result["opened_at"]),
        expires_at=parse_datetime(result["expires_at"]) if result.get("expires_at") else None,
    )
    notify.notify_breakglass(
        patient_id=patient_id,
        record_id=record_id,
        clinician_id=ctx["subject_id"],
        facility_id=result["facility_id"],
        correlation_id=result["correlation_id"],
        reason_code=reason_code,
    )
    request.session.pop("clinician.identified", None)

    # The decrypted payload is shown on this response only -- never stored.
    plaintext = None
    if result.get("plaintext_b64"):
        plaintext = _pretty(base64.b64decode(result["plaintext_b64"]), result.get("content_type") or "")
    ctx = _case_ctx(request, case)
    ctx.update({"just_opened": True, "plaintext": plaintext, "unlock": result})
    response = render(request, "clinician/case.html", ctx)
    response["Cache-Control"] = "no-store"
    return response


def _pretty(plaintext: bytes, content_type: str) -> str:
    text = plaintext.decode("utf-8", errors="replace")
    if "json" in content_type or text.lstrip().startswith("{"):
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            return text
    return text


# --- Emergency sessions ----------------------------------------------------------------


def _case_ctx(request: Any, case: BreakglassCase) -> dict[str, Any]:
    ctx = _base_ctx(request, "Emergency session")
    _refresh(case)
    try:
        entries = store_reader.audit_by_correlation(case.correlation_id)
        store_error = None
    except Exception as exc:  # noqa: BLE001
        entries, store_error = [], str(exc)
    for e in entries:
        if isinstance(e.get("event_data"), str):
            e["event_data"] = json.loads(e["event_data"])
        if e["event_type"] in store_reader.LIFECYCLE_EVENT_TYPES and (
            e["event_data"].get("to_state") == "expired"
        ) and case.status == CaseStatus.OPEN:
            case.status = CaseStatus.EXPIRED
            case.save(update_fields=["status"])
    share_cards = _share_cards(case)
    ctx.update(
        {
            "case": case,
            "entries": entries,
            "store_error": store_error,
            "share_cards": share_cards,
            "directory": PatientDirectory.objects.filter(subject_id=case.patient_id).first(),
            "search_results": None,
        }
    )
    return ctx


def _share_cards(case: BreakglassCase) -> list[dict[str, Any]]:
    held = {s.get("holder"): s for s in (case.shares or [])}
    return [
        {
            "kicker": "Share 1 of 3",
            "who": "Attending clinician",
            "note": "Released against the validated assertion and a certificate that cross-certifies back to the federation root.",
            "state": "PRESENTED" if "clinician" in held else "NOT PRESENTED",
            "held": "clinician" in held,
            "x": held.get("clinician", {}).get("x"),
        },
        {
            "kicker": "Share 2 of 3",
            "who": "Home authority",
            "note": "The patient's own authority, or a federated delegate when it is unreachable. Not requested: the threshold was met without it.",
            "state": "NOT REQUESTED",
            "held": False,
            "x": None,
        },
        {
            "kicker": "Share 3 of 3",
            "who": "Audit service",
            "note": "Held back until a chain entry is committed and its new head returned. No commit, no share.",
            "state": (
                f"RELEASED AFTER SEQ {held['audit-service'].get('audit_entry_seq')}"
                if "audit-service" in held
                else "WITHHELD"
            ),
            "held": "audit-service" in held,
            "x": held.get("audit-service", {}).get("x"),
        },
    ]


@role_required(Role.CLINICIAN)
def cases(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Emergency sessions")
    ctx["cases"] = [
        _refresh(c) for c in BreakglassCase.objects.filter(clinician_id=ctx["subject_id"])
    ]
    return render(request, "clinician/cases.html", ctx)


@role_required(Role.CLINICIAN)
def case_detail(request: Any, pk: int) -> HttpResponse:
    case = get_object_or_404(BreakglassCase, pk=pk, clinician_id=request.user.profile.subject_id)
    ctx = _case_ctx(request, case)
    if request.method == "POST":
        term = request.POST.get("search_term", "").strip()
        ctx["search_term"] = term
        if not term:
            ctx["search_error"] = "Enter a term to derive a token for."
        else:
            try:
                hits = services.facility_emergency_search(case.facility_id, case.record_id, term)
                ctx["search_results"] = hits
                ctx["search_state"] = "TOKEN LIVE" if case.status == CaseStatus.OPEN else "TOKEN DEAD"
            except ServiceError as exc:
                ctx["search_error"] = f"{exc.service}: {exc.detail}"
                ctx["search_state"] = "TOKEN DEAD"
                if exc.status == 403 and case.status == CaseStatus.OPEN:
                    case.status = CaseStatus.EXPIRED
                    case.save(update_fields=["status"])
    return render(request, "clinician/case.html", ctx)


# --- Consent requests -----------------------------------------------------------------


@role_required(Role.CLINICIAN)
def consent_request(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Request consent")
    patient_id = (request.POST.get("patient_id") or request.GET.get("patient_id") or "").strip()
    discovery = (request.session.get(_DISCOVERY_SESSION_KEY) or {}).get(patient_id)
    ctx.update(
        {
            "patient_id": patient_id,
            "directory": PatientDirectory.objects.filter(subject_id=patient_id).first() if patient_id else None,
            "discovered": discovery,
            "mine": ConsentRecord.objects.filter(requester_id=ctx["subject_id"])[:20],
            "ttl_days": REQUEST_TTL_DAYS,
        }
    )
    if request.method != "POST":
        return render(request, "clinician/consent_request.html", ctx)

    action = request.POST.get("action")
    if not patient_id:
        ctx["error"] = "Enter or identify a patient first."
        return render(request, "clinician/consent_request.html", ctx, status=400)
    if action == "discover":
        try:
            ids = services.facility_discover(ctx["facility_id"], patient_id)
        except ServiceError as exc:
            ctx["error"] = f"Discovery refused — {exc.service}: {exc.detail}"
            return render(request, "clinician/consent_request.html", ctx, status=502)
        found = []
        for rid in ids:
            try:
                meta = store_reader.record_meta(rid)
            except Exception:  # noqa: BLE001
                meta = None
            found.append(meta or {"record_id": rid, "facility_id": "?", "content_type": "?"})
        session = request.session.get(_DISCOVERY_SESSION_KEY) or {}
        session[patient_id] = found
        request.session[_DISCOVERY_SESSION_KEY] = session
        ctx["discovered"] = found
        return render(request, "clinician/consent_request.html", ctx)

    scope = [r for r in request.POST.getlist("scope") if r]
    purpose = request.POST.get("purpose", "").strip()
    ctx.update({"purpose": purpose})
    if not scope or not purpose:
        ctx["error"] = "Choose at least one record and state the clinical purpose."
        return render(request, "clinician/consent_request.html", ctx, status=400)
    try:
        signed = services.custodian_sign_consent_request(
            ctx["subject_id"],
            patient_id=patient_id,
            scope=scope,
            purpose=purpose,
            ttl_days=REQUEST_TTL_DAYS,
        )
    except ServiceError as exc:
        ctx["error"] = f"Request not signed — {exc.service}: {exc.detail}"
        return render(request, "clinician/consent_request.html", ctx, status=403 if exc.is_denial else 503)
    correlation_id = f"consent-{signed['request_id']}"
    row = ConsentRecord.objects.create(
        request_id=signed["request_id"],
        patient_id=patient_id,
        requester_id=ctx["subject_id"],
        requester_facility_id=ctx["facility_id"] or "",
        scope=list(signed["scope"]),
        purpose=purpose,
        requested_at=signed["requested_at"],
        request_expires_at=signed["expires_at"],
        request_json=signed,
        correlation_id=correlation_id,
    )
    notify.notify_consent_request(
        patient_id=patient_id, requester_id=ctx["subject_id"], scope=list(row.scope), correlation_id=correlation_id
    )
    messages.success(request, f"Signed request {str(row.request_id)[:8]}… sent to {patient_id} for a decision.")
    return redirect("clinician:consent_request")


@role_required(Role.CLINICIAN)
def consent_read(request: Any, request_id: str) -> HttpResponse:
    """Read under a live grant: the custodian presents the grant + attribute keys."""
    ctx = _base_ctx(request, "Read under consent")
    row = get_object_or_404(ConsentRecord, request_id=request_id, requester_id=ctx["subject_id"])
    record_id = request.POST.get("record_id") or request.GET.get("record_id") or (row.scope[0] if row.scope else "")
    ctx.update({"row": row, "record_id": record_id})
    if request.method != "POST":
        return render(request, "clinician/consent_read.html", ctx)
    if row.status != ConsentStatus.GRANTED or not row.grant_json:
        ctx["denied"] = f"grant status is {row.status}; only a live GRANTED grant authorises a read"
        return render(request, "clinician/consent_read.html", ctx, status=403)
    correlation_id = f"{row.correlation_id}-read-{uuid4().hex[:8]}"
    try:
        meta = store_reader.record_meta(record_id)
    except Exception:  # noqa: BLE001
        meta = None
    facility_id = (meta or {}).get("facility_id") or ctx["facility_id"]
    try:
        result = services.custodian_read(
            ctx["subject_id"],
            record_id=record_id,
            facility_id=facility_id,
            correlation_id=correlation_id,
            grant=row.grant_json,
        )
    except ServiceError as exc:
        ctx.update({"denied": exc.detail, "correlation_id": correlation_id})
        return render(request, "clinician/consent_read.html", ctx, status=403 if exc.is_denial else 503)
    ctx.update(
        {
            "plaintext": _pretty(base64.b64decode(result["plaintext_b64"]), result.get("content_type") or ""),
            "correlation_id": correlation_id,
            "attributes_presented": result.get("attributes_presented", []),
        }
    )
    response = render(request, "clinician/consent_read.html", ctx)
    response["Cache-Control"] = "no-store"
    return response
