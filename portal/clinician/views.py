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
import secrets
from datetime import date, timedelta
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
from portal_core.clinical import (
    SEARCH_VOCABULARY,
    episode_groups,
    expand_search_terms,
    name_matches,
    normalized_name,
    record_label,
)

from accounts.models import PatientDirectory, Role
from ledger.models import (
    BreakglassCase,
    CaseStatus,
    ConsentRecord,
    ConsentStatus,
    CareEpisode,
)

REASON_CODES = [
    ("cardiac_arrest", "CARDIAC-ARREST — cardiac arrest in progress"),
    ("respiratory_failure", "RESP-FAILURE — acute respiratory failure"),
    ("unconscious_patient", "UNCONSCIOUS — unresponsive on arrival"),
    ("major_trauma", "TRAUMA — major trauma admission"),
    ("stroke", "STROKE — suspected acute stroke"),
    ("severe_allergic_reaction", "ANAPHYLAXIS — severe allergic reaction"),
    ("overdose", "Overdose / poisoning"),
    ("sepsis", "Sepsis"),
    ("seizure", "Seizure / status epilepticus"),
    ("obstetric_emergency", "Obstetric emergency"),
    ("diabetic_ketoacidosis", "Diabetic ketoacidosis"),
    ("haemorrhage", "Major haemorrhage"),
    ("other_life_threatening", "OTHER — other life-threatening condition"),
]
REQUEST_TTL_DAYS = 7
_DISCOVERY_SESSION_KEY = "clinician.discovery"
# One-time token for the declare form (ADR-0065): a reloaded or re-sent
# declaration finds it already spent and opens nothing.
_DECLARE_TOKEN_KEY = "clinician.declare_token"


def _session_safe(meta: dict[str, Any]) -> dict[str, Any]:
    """Store metadata carries datetimes; the session store needs JSON scalars."""
    return {
        k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in meta.items()
    }


def _discover(facility_id: str, patient_id: str) -> list[dict[str, Any]]:
    """Federated discovery + read-only metadata for display (decoration only)."""
    found = []
    for rid in services.facility_discover(facility_id, patient_id):
        try:
            meta = store_reader.record_meta(rid)
        except Exception:  # noqa: BLE001 - metadata is decoration only
            meta = None
        found.append(
            _session_safe(meta)
            if meta
            else {"record_id": rid, "facility_id": "?", "content_type": "?"}
        )
    return found


def _subject(subject_id: str) -> dict[str, Any] | None:
    try:
        return services.custodian_subject(subject_id)
    except ServiceError:
        return None


def _refresh(case: BreakglassCase) -> BreakglassCase:
    if (
        case.status == CaseStatus.OPEN
        and case.expires_at
        and (
            case.expires_at <= dj_tz.now()
            or (
                case.episode
                and (case.episode.closed_at or case.episode.expires_at <= dj_tz.now())
            )
        )
    ):
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
            ("clinician:profile", "Your profile"),
        ],
    }


# --- Profile -------------------------------------------------------------------------


@role_required(Role.CLINICIAN)
def profile(request: Any) -> HttpResponse:
    """The clinician's own details, read only; nothing here changes access."""
    ctx = _base_ctx(request, "Your profile")
    ctx["requests"] = request.user.requests.all()
    return render(request, "profile.html", ctx)


# --- Overview ------------------------------------------------------------------------


@role_required(Role.CLINICIAN)
def home(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Overview")
    me = ctx["subject_id"]
    ctx.update(
        {
            "requests": request.user.requests.all(),
            "consents": ConsentRecord.objects.filter(requester_id=me)[:10],
            "cases": [
                _refresh(c) for c in BreakglassCase.objects.filter(clinician_id=me)[:10]
            ],
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
        dob = date.fromisoformat(dob_raw) if dob_raw else None
    except ValueError:
        ctx["error"] = "Date of birth must be YYYY-MM-DD."
        return render(request, "clinician/identify.html", ctx, status=400)
    if not family and not given:
        ctx["error"] = "Enter a name, or start an unidentified-patient encounter."
        return render(request, "clinician/identify.html", ctx, status=400)
    qs = PatientDirectory.objects.all()
    if dob:
        qs = qs.filter(date_of_birth=dob)
    candidates = []
    for candidate in qs.order_by("given_name", "subject_id"):
        names = [candidate.family_name, candidate.full_name, *candidate.aliases]
        family_ok = not family or any(name_matches(family, n) for n in names)
        given_ok = (
            not given
            or normalized_name(candidate.given_name).startswith(normalized_name(given))
            or name_matches(given, candidate.given_name)
        )
        if family_ok and given_ok:
            candidates.append(candidate)
        if len(candidates) == 25:
            break

    # Log before showing: a lookup that cannot be recorded is not served.
    # Nothing about what was typed enters the chain, not even a hash: names
    # and dates of birth have too little entropy to hide (ADR-0085).
    correlation_id = f"lookup-{uuid4()}"
    seq = notify.append_audit(
        event_type=notify.EVENT_PATIENT_LOOKUP,
        event_data={
            "clinician_id": ctx["subject_id"],
            "facility_id": ctx["facility_id"],
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
    ctx.update(
        {"candidates": candidates, "lookup_seq": seq, "correlation_id": correlation_id}
    )
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
        messages.error(
            request,
            "The audit service did not record the selection; nothing carried forward.",
        )
        return redirect("clinician:identify")
    request.session["clinician.identified"] = {
        "patient_id": patient_id,
        "correlation_id": correlation_id,
    }
    episode = (
        CareEpisode.objects.filter(
            pk=request.session.get("clinician.episode"),
            clinician_id=ctx["subject_id"],
            patient_id=patient_id,
            closed_at__isnull=True,
            expires_at__gt=dj_tz.now(),
        ).first()
        if request.session.get("clinician.episode")
        else None
    )
    if episode is None:
        episode = CareEpisode.objects.create(
            patient_id=patient_id,
            clinician_id=ctx["subject_id"],
            facility_id=ctx["facility_id"],
            expires_at=dj_tz.now()
            + timedelta(seconds=settings.EMERGENCY_DURATION_SECONDS),
        )
    request.session["clinician.episode"] = str(episode.pk)
    target = (
        "clinician:consent_request"
        if request.POST.get("next") == "consent"
        else "clinician:breakglass"
    )
    return redirect(f"{_url(target)}?patient_id={patient_id}")


def _url(name: str) -> str:
    from django.urls import reverse

    return reverse(name)


# --- Break-glass ----------------------------------------------------------------------


def _identified(request: Any) -> dict[str, Any]:
    """The patient picked in this session's logged lookup (ADR-0033), if any.

    Kept server-side in the session, never taken from the form: the
    break-glass page acts only on the patient the logged lookup selected,
    under that lookup's correlation id (review F41).
    """
    ident = request.session.get("clinician.identified") or {}
    episode_id = request.session.get("clinician.episode")
    if (
        episode_id
        and not CareEpisode.objects.filter(
            pk=episode_id,
            clinician_id=request.user.profile.subject_id,
            patient_id=ident.get("patient_id"),
            closed_at__isnull=True,
            expires_at__gt=dj_tz.now(),
        ).exists()
    ):
        return {}
    return ident


def _form(request: Any, ctx: dict[str, Any], status: int = 200) -> HttpResponse:
    """Render the break-glass form with a fresh one-time declare token.

    Every render replaces the token, so only the newest form can declare and
    a declaration can be sent once (ADR-0065).
    """
    token = secrets.token_urlsafe(32)
    request.session[_DECLARE_TOKEN_KEY] = token
    ctx["declare_token"] = token
    return render(request, "clinician/breakglass.html", ctx, status=status)


def _spend_declare_token(request: Any) -> bool:
    """Consume the session's declare token; ``True`` only if the form sent it."""
    expected = request.session.pop(_DECLARE_TOKEN_KEY, None)
    sent = request.POST.get("declare_token", "")
    return bool(expected) and secrets.compare_digest(
        expected.encode("utf-8"), sent.encode("utf-8")
    )


@role_required(Role.CLINICIAN)
def breakglass(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Emergency break-glass")
    ident = _identified(request)
    patient_id = ident.get("patient_id", "")
    requested = (
        request.POST.get("patient_id") or request.GET.get("patient_id") or ""
    ).strip()
    if requested and requested != patient_id:
        # A raw patient_id would skip the patient.lookup event (review F41).
        ctx["error"] = (
            "That patient was not selected through a logged directory lookup — "
            "identify the patient first."
        )
        return _form(request, ctx, status=400)
    directory = (
        PatientDirectory.objects.filter(subject_id=patient_id).first()
        if patient_id
        else None
    )
    discovery = (request.session.get(_DISCOVERY_SESSION_KEY) or {}).get(patient_id)
    ctx.update(
        {
            "patient_id": patient_id,
            "directory": directory,
            "reason_codes": REASON_CODES,
            "discovered": discovery,
            "duration": int(settings.EMERGENCY_DURATION_SECONDS),
            "assertion_ttl": settings.ASSERTION_TTL_SECONDS,
        }
    )
    if request.method != "POST":
        return _form(request, ctx)

    action = request.POST.get("action")
    if not patient_id:
        ctx["error"] = (
            "Identify the patient first — an assertion is bound to a patient_id."
        )
        return _form(request, ctx, status=400)

    if action == "discover":
        try:
            found = _discover(ctx["facility_id"], patient_id)
        except ServiceError as exc:
            ctx["error"] = f"Discovery refused — {exc.service}: {exc.detail}"
            return _form(request, ctx, status=502)
        session = request.session.get(_DISCOVERY_SESSION_KEY) or {}
        session[patient_id] = found
        request.session[_DISCOVERY_SESSION_KEY] = session
        ctx["discovered"] = found
        for record in found:
            record["label"] = record_label(record)
        return _form(request, ctx)

    # action == "declare": one declaration may cover several records (ADR-0061).
    # The one-time token is spent before anything else, so a reload of this
    # POST's response, or any re-send, declares nothing (ADR-0065).
    if action != "declare":
        ctx["error"] = "Unknown action."
        return _form(request, ctx, status=400)
    if not _spend_declare_token(request):
        ctx["error"] = (
            "This declaration was already sent, or the form is out of date. "
            "Nothing was opened; review the records and declare again if needed."
        )
        return _form(request, ctx, status=409)
    record_ids = [
        rid.strip()
        for rid in (
            request.POST.getlist("record_ids") or [request.POST.get("record_id", "")]
        )
        if rid.strip()
    ]
    reason_code = request.POST.get("reason_code", "")
    justification = request.POST.get("justification", "").strip()
    sensitive_justification = request.POST.get("sensitive_justification", "").strip()
    ctx.update(
        {
            "reason_code": reason_code,
            "justification": justification,
            "record_ids": record_ids,
        }
    )
    if (
        not record_ids
        or reason_code not in dict(REASON_CODES)
        or len(justification) < 20
    ):
        ctx["error"] = (
            "Choose at least one discovered record and a reason, and explain the immediate clinical need (at least 20 characters)."
        )
        return _form(request, ctx, status=400)
    by_id = {r["record_id"]: r for r in discovery or []}
    if not set(record_ids) <= by_id.keys():
        ctx["error"] = "Choose records from this patient's discovery results."
        return _form(request, ctx, status=400)

    episode = (
        CareEpisode.objects.filter(pk=request.session.get("clinician.episode")).first()
        if request.session.get("clinician.episode")
        else None
    )
    outcomes = [
        _declare(
            ctx,
            ident,
            by_id[rid],
            episode,
            reason_code=reason_code,
            justification=justification,
            sensitive_justification=sensitive_justification,
        )
        for rid in dict.fromkeys(record_ids)
    ]
    # Keep this explicit patient binding until the care episode closes.

    if len(outcomes) > 1:
        for case, _result, exc in outcomes:
            if exc is not None:
                messages.error(
                    request,
                    f"{case.record_id}: break-glass refused — {exc.service}: {exc.detail}",
                )
        opened = sum(1 for _c, _r, exc in outcomes if exc is None)
        if opened:
            messages.success(
                request,
                f"Opened {opened} record{'s' if opened != 1 else ''} under one declaration. "
                "Each was authorized, audited and notified separately; open a case "
                "to read its record.",
            )
        return redirect("clinician:cases")

    case, result, exc = outcomes[0]
    if exc is not None:
        ctx.update(
            {
                "error": f"Break-glass refused — {exc.service}: {exc.detail}",
                "failed_case": case,
            }
        )
        return _form(request, ctx, status=403 if exc.is_denial else 503)

    # The decrypted payload is shown on this response only -- never stored.
    ctx = _case_ctx(request, case)
    ctx.update({"just_opened": True, "unlock": result, **_record_display(result)})
    response = render(request, "clinician/case.html", ctx)
    response["Cache-Control"] = "no-store"
    return response


def _declare(
    ctx: dict[str, Any],
    ident: dict[str, Any],
    record: dict[str, Any],
    episode: CareEpisode | None,
    *,
    reason_code: str,
    justification: str,
    sensitive_justification: str,
) -> tuple[BreakglassCase, dict[str, Any], ServiceError | None]:
    """Break-glass one discovered record at the facility that holds it."""
    record_id = record["record_id"]
    patient_id = ident["patient_id"]
    correlation_id = f"{ident['correlation_id']}-{uuid4().hex[:8]}"
    # The record's own node holds its session, so every viewer joins there,
    # whichever facility they work at (ADR-0057, ADR-0061). "?" = metadata gap.
    facility_id = record.get("facility_id")
    if facility_id in (None, "", "?"):
        facility_id = ctx["facility_id"]
    duration = settings.EMERGENCY_DURATION_SECONDS
    if episode:
        duration = min(
            duration, max(1, (episode.expires_at - dj_tz.now()).total_seconds())
        )
    try:
        result = services.custodian_breakglass(
            ctx["subject_id"],
            patient_id=patient_id,
            record_id=record_id,
            reason_code=reason_code,
            correlation_id=correlation_id,
            facility_id=facility_id,
            emergency_duration_seconds=duration,
            justification=justification,
            sensitive_justification=sensitive_justification,
        )
    except ServiceError as exc:
        case = BreakglassCase.objects.create(
            correlation_id=f"{correlation_id}#{uuid4().hex[:6]}",
            record_id=record_id,
            patient_id=patient_id,
            clinician_id=ctx["subject_id"],
            facility_id=facility_id or "",
            reason_code=reason_code,
            justification=justification,
            sensitive_justification=sensitive_justification,
            episode=episode,
            status=CaseStatus.FAILED,
            failure_reason=f"{exc.service}: {exc.detail}",
        )
        return case, {}, exc

    case = BreakglassCase.objects.create(
        correlation_id=result["correlation_id"],
        record_id=record_id,
        patient_id=patient_id,
        clinician_id=ctx["subject_id"],
        facility_id=result["facility_id"],
        reason_code=reason_code,
        justification=justification,
        sensitive_justification=sensitive_justification,
        episode=episode,
        assertion_id=result["assertion_id"],
        status=CaseStatus.OPEN,
        shares=result["shares_presented"],
        audit_entry_seq=next(
            (
                s.get("audit_entry_seq")
                for s in result["shares_presented"]
                if s.get("audit_entry_seq")
            ),
            None,
        ),
        opened_at=parse_datetime(result["opened_at"]),
        expires_at=(
            parse_datetime(result["expires_at"]) if result.get("expires_at") else None
        ),
    )
    notify.notify_breakglass(
        patient_id=patient_id,
        record_id=record_id,
        clinician_id=ctx["subject_id"],
        facility_id=result["facility_id"],
        correlation_id=result["correlation_id"],
        reason_code=reason_code,
        record_title=(record.get("clinical") or {}).get("title", ""),
        facility_name=record.get("facility_name", ""),
    )
    return case, result, None


# Passive types shown in the page from the one audited fetch (no second key
# release); every other binary type is offered as a download (review F42).
_EMBED_TYPES = {"application/pdf": "pdf", "image/png": "image", "image/jpeg": "image"}


def _record_display(result: dict[str, Any]) -> dict[str, Any]:
    """Template context for a decrypted record; its content type is the uploader's claim."""
    if not result.get("plaintext_b64"):
        return {}
    raw = base64.b64decode(result["plaintext_b64"])
    content_type = (result.get("content_type") or "").split(";")[0].strip().lower()
    if not content_type or content_type.startswith("text/") or "json" in content_type:
        return {"plaintext": _pretty(raw, content_type)}
    kind = _EMBED_TYPES.get(content_type, "download")
    mime = content_type if kind != "download" else "application/octet-stream"
    return {
        "record_kind": kind,
        "record_type": content_type,
        "record_bytes": len(raw),
        "record_uri": f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}",
    }


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
        if (
            e["event_type"] in store_reader.LIFECYCLE_EVENT_TYPES
            and (e["event_data"].get("to_state") == "expired")
            and case.status == CaseStatus.OPEN
        ):
            case.status = CaseStatus.EXPIRED
            case.save(update_fields=["status"])
    share_cards = _share_cards(case)
    ctx.update(
        {
            "case": case,
            "entries": entries,
            "store_error": store_error,
            "share_cards": share_cards,
            "directory": PatientDirectory.objects.filter(
                subject_id=case.patient_id
            ).first(),
            "search_results": None,
            "search_vocabulary": SEARCH_VOCABULARY,
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
        _refresh(c)
        for c in BreakglassCase.objects.filter(clinician_id=ctx["subject_id"])
    ]
    return render(request, "clinician/cases.html", ctx)


@role_required(Role.CLINICIAN)
def case_detail(request: Any, pk: int) -> HttpResponse:
    case = get_object_or_404(
        BreakglassCase, pk=pk, clinician_id=request.user.profile.subject_id
    )
    ctx = _case_ctx(request, case)
    if request.method == "POST":
        term = request.POST.get("search_term", "").strip()
        ctx["search_term"] = term
        if not term:
            ctx["search_error"] = "Enter a term to derive a token for."
        else:
            try:
                ctx["search_terms"] = expand_search_terms(term)
                ctx["search_results"] = sorted(
                    {
                        rid
                        for t in ctx["search_terms"]
                        for rid in services.facility_emergency_search(
                            case.facility_id,
                            case.record_id,
                            t,
                            case.clinician_id,
                            case.correlation_id,
                        )
                    }
                )
                ctx["search_state"] = (
                    "TOKEN LIVE" if case.status == CaseStatus.OPEN else "TOKEN DEAD"
                )
            except ServiceError as exc:
                ctx["search_error"] = f"{exc.service}: {exc.detail}"
                ctx["search_state"] = "TOKEN DEAD"
                if exc.status == 403 and case.status == CaseStatus.OPEN:
                    case.status = CaseStatus.EXPIRED
                    case.save(update_fields=["status"])
    status = _show_record(case, ctx)
    response = render(request, "clinician/case.html", ctx, status=status)
    response["Cache-Control"] = "no-store"
    return response


def _show_record(case: BreakglassCase, ctx: dict[str, Any]) -> int:
    """Put the decrypted record on the page while the window is open (ADR-0062).

    Every page load joins the open session (ADR-0057): a fresh one-time
    assertion, the same threshold, the audit entry committed before share 3
    is released, no new transition and no extension of the window. The case's
    correlation id is reused so every view lands in this case's chain
    segment. Nothing is stored; the payload lives in this response only.
    """
    if case.status != CaseStatus.OPEN:
        return 200
    try:
        result = services.custodian_breakglass(
            case.clinician_id,
            patient_id=case.patient_id,
            record_id=case.record_id,
            reason_code=case.reason_code,
            correlation_id=case.correlation_id,
            facility_id=case.facility_id,
            justification=case.justification,
            sensitive_justification=case.sensitive_justification,
            # A page view joins the open session or fails; it never opens a
            # new emergency, even if the window closed a moment ago (ADR-0065).
            join_only=True,
        )
    except ServiceError as exc:
        ctx["view_error"] = f"{exc.service}: {exc.detail}"
        return 403 if exc.is_denial else 503
    ctx.update(_record_display(result))
    return 200


# --- Consent requests -----------------------------------------------------------------


@role_required(Role.CLINICIAN)
def consent_request(request: Any) -> HttpResponse:
    ctx = _base_ctx(request, "Request consent")
    patient_id = (
        request.POST.get("patient_id") or request.GET.get("patient_id") or ""
    ).strip()
    discovery = (request.session.get(_DISCOVERY_SESSION_KEY) or {}).get(patient_id)
    ctx.update(
        {
            "patient_id": patient_id,
            "directory": (
                PatientDirectory.objects.filter(subject_id=patient_id).first()
                if patient_id
                else None
            ),
            "discovered": discovery,
            "mine": ConsentRecord.objects.filter(requester_id=ctx["subject_id"])[:20],
            "episodes": episode_groups(discovery or []),
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
            found = _discover(ctx["facility_id"], patient_id)
        except ServiceError as exc:
            ctx["error"] = f"Discovery refused — {exc.service}: {exc.detail}"
            return render(request, "clinician/consent_request.html", ctx, status=502)
        session = request.session.get(_DISCOVERY_SESSION_KEY) or {}
        session[patient_id] = found
        request.session[_DISCOVERY_SESSION_KEY] = session
        ctx["discovered"] = found
        ctx["episodes"] = episode_groups(found)
        return render(request, "clinician/consent_request.html", ctx)

    scope = [r for r in request.POST.getlist("scope") if r]
    selected_episodes = request.POST.getlist("episodes")
    groups = episode_groups(discovery or [])
    if selected_episodes:
        if not set(selected_episodes) <= {g["key"] for g in groups}:
            return HttpResponse(
                "Choose an episode from the discovered results", status=400
            )
        scope = [
            r["record_id"]
            for g in groups
            if g["key"] in selected_episodes
            for r in g["records"]
        ]
    if not set(scope) <= {r["record_id"] for r in discovery or []}:
        return HttpResponse(
            "Scope must come from this patient's discovery results", status=400
        )
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
        return render(
            request,
            "clinician/consent_request.html",
            ctx,
            status=403 if exc.is_denial else 503,
        )
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
        episode_label=", ".join(selected_episodes)
        or "Selected records (episode unknown)",
        record_labels=[
            record_label(r) for r in discovery or [] if r["record_id"] in scope
        ],
    )
    notify.notify_consent_request(
        patient_id=patient_id,
        requester_id=ctx["subject_id"],
        scope=list(row.scope),
        correlation_id=correlation_id,
    )
    messages.success(
        request,
        f"Signed request {str(row.request_id)[:8]}… sent to {patient_id} for a decision.",
    )
    return redirect("clinician:consent_request")


@role_required(Role.CLINICIAN)
def consent_read(request: Any, request_id: str) -> HttpResponse:
    """Read under a live grant: the custodian presents the grant + attribute keys."""
    ctx = _base_ctx(request, "Read under consent")
    row = get_object_or_404(
        ConsentRecord, request_id=request_id, requester_id=ctx["subject_id"]
    )
    record_id = (
        request.POST.get("record_id")
        or request.GET.get("record_id")
        or (row.scope[0] if row.scope else "")
    )
    ctx.update({"row": row, "record_id": record_id})
    if request.method != "POST":
        return render(request, "clinician/consent_read.html", ctx)
    if row.status != ConsentStatus.GRANTED or not row.grant_json:
        ctx["denied"] = (
            f"grant status is {row.status}; only a live GRANTED grant authorises a read"
        )
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
        return render(
            request,
            "clinician/consent_read.html",
            ctx,
            status=403 if exc.is_denial else 503,
        )
    ctx.update(
        {
            **_record_display(result),
            "correlation_id": correlation_id,
            "attributes_presented": result.get("attributes_presented", []),
        }
    )
    response = render(request, "clinician/consent_read.html", ctx)
    response["Cache-Control"] = "no-store"
    return response
