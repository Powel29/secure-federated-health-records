"""Admin / audit portal (P4-9). Read-only over the audit chain and federation state.

Reads the P0-8 store through the read-only ``store`` alias (audit log, records,
lifecycle), asks the Audit Service to re-verify the chain from genesis, and
health-checks every federation process. It can view pending registration
requests, but *approving* one only reaches the ``issue_credential`` stub:
issuance is the authority's job (ADR-0021), never the portal's. Nothing here
holds a key or changes access.
"""

from __future__ import annotations

import json
from typing import Any

from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone as dj_tz
from portal_core import services, store_reader, stubs
from portal_core.access import role_required
from portal_core.services import ServiceError

from accounts.models import RegistrationRequest, RequestStatus, Role
from ledger.models import BreakglassCase, CaseStatus, ConsentRecord, PatientNotification

_PROCESS_HOLDS = {
    "store": "Ciphertext, wrapped keys, coded index",
    "facility-a": "Clinician certificates, home-authority link",
    "facility-b": "Clinician certificates only",
    "authority-med": "Attribute keys · role",
    "authority-net": "Attribute keys · specialty, facility, owner",
    "audit": "Hash chain, break-glass share 3",
    "custodian": "Subject key agent: signing keys, credentials, share 1",
}


def _store(fn: Any, *args: Any, default: Any = None) -> tuple[Any, str | None]:
    try:
        return fn(*args), None
    except Exception as exc:  # noqa: BLE001 - display-only, never fatal
        return default, str(exc)


def _base_ctx(screen: str) -> dict[str, Any]:
    return {
        "crumb_role": "Admin & audit portal",
        "crumb_screen": screen,
        "nav": [
            ("admin_audit:home", "Overview"),
            ("admin_audit:trace", "Break-glass audit trail"),
            ("admin_audit:cases", "Break-glass case review"),
            ("admin_audit:federation", "Federation & key custody"),
            ("admin_audit:registrations", "Registrations"),
        ],
    }


def _decode(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for e in entries:
        if isinstance(e.get("event_data"), str):
            e["event_data"] = json.loads(e["event_data"])
        e["summary"] = _summary(e)
        e["is_commit"] = e["event_type"] in store_reader.BREAKGLASS_EVENT_TYPES
    return entries


def _summary(e: dict[str, Any]) -> str:
    d = e.get("event_data") or {}
    et = e["event_type"]
    if et == "patient.lookup":
        sel = d.get("selected_patient_id")
        return f"{d.get('candidate_count', 0)} candidates, " + (f"selected {sel}" if sel else "none selected")
    if et == "federation.discovery":
        return f"{d.get('record_count', 0)} records, patient hashed"
    if et in ("breakglass_share_released", "breakglass_share_release"):
        return f"share 3 committed BEFORE release · assertion {str(d.get('assertion_id', ''))[:8]}"
    if et == "federation.rewrap":
        return f"{d.get('record_id')} re-wrapped by PRE for {d.get('target_actor_id')}"
    if et in store_reader.LIFECYCLE_EVENT_TYPES:
        return f"{d.get('from_state', '?')} → {d.get('to_state', '?')} · {d.get('record_id', '')}"
    if et == "access_granted":
        return f"{d.get('requester_id')} read {d.get('record_id')} via {d.get('access_via')}"
    if et == "access_denied":
        return f"{d.get('requester_id')} denied on {d.get('record_id')} by {d.get('denied_by')}"
    if et == "patient.notification":
        return f"{d.get('kind')} notification to {d.get('patient_id')}"
    if et == "consent.decision":
        return f"{d.get('patient_id')} {d.get('status')} {d.get('grantee_id')} on {', '.join(d.get('scope', []))}"
    if et == "genesis":
        return "chain genesis h_0"
    return ", ".join(f"{k}={v}" for k, v in list(d.items())[:4])


def _links_intact(entries: list[dict[str, Any]]) -> bool | None:
    """Within a segment, each entry's prev_hash must equal the prior entry's hash."""
    if len(entries) < 2:
        return None
    for prev, cur in zip(entries, entries[1:], strict=False):
        if cur["seq"] == prev["seq"] + 1 and cur["prev_hash_hex"] != prev["entry_hash_hex"]:
            return False
    return True


def _verify() -> dict[str, Any]:
    try:
        return {"ok": True, **services.audit_verify()}
    except ServiceError as exc:
        return {"ok": False, "verified": False, "detail": exc.detail}


# --- Overview -------------------------------------------------------------------------


@role_required(Role.ADMIN)
def home(request: Any) -> HttpResponse:
    ctx = _base_ctx("Overview")
    stats, store_error = _store(store_reader.chain_stats, default={"head": None, "length": 0})
    recent, _ = _store(store_reader.recent_audit, 12, default=[])
    counts, _ = _store(store_reader.event_type_counts, default=[])
    ctx.update(
        {
            "stats": stats,
            "store_error": store_error,
            "verify": _verify(),
            "recent": _decode(recent),
            "event_counts": counts,
            "cases_open": BreakglassCase.objects.filter(status=CaseStatus.OPEN).count(),
            "cases_total": BreakglassCase.objects.count(),
            "consents_live": ConsentRecord.objects.filter(status="granted").count(),
            "notifications": PatientNotification.objects.count(),
            "pending": RegistrationRequest.objects.filter(status=RequestStatus.PENDING).count(),
        }
    )
    return render(request, "admin_audit/home.html", ctx)


# --- Trace by correlation ID ------------------------------------------------------


@role_required(Role.ADMIN)
def trace(request: Any) -> HttpResponse:
    ctx = _base_ctx("Break-glass audit trail")
    cid = request.GET.get("cid", "").strip()
    stats, store_error = _store(store_reader.chain_stats, default={"head": None, "length": 0})
    recent_flows, _ = _store(store_reader.breakglass_correlations, 10, default=[])
    ctx.update({"cid": cid, "stats": stats, "store_error": store_error, "verify": _verify(), "flows": recent_flows})
    if cid:
        entries, err = _store(store_reader.audit_by_correlation, cid, default=[])
        entries = _decode(entries)
        ctx.update(
            {
                "entries": entries,
                "links_intact": _links_intact(entries),
                "case": BreakglassCase.objects.filter(correlation_id=cid).first(),
                "consent": ConsentRecord.objects.filter(correlation_id=cid).first(),
                "notes": PatientNotification.objects.filter(correlation_id=cid),
                "store_error": store_error or err,
            }
        )
    return render(request, "admin_audit/trace.html", ctx)


# --- Break-glass case review --------------------------------------------------------


@role_required(Role.ADMIN)
def cases(request: Any) -> HttpResponse:
    ctx = _base_ctx("Break-glass case review")
    flows, store_error = _store(store_reader.breakglass_correlations, 100, default=[])
    by_cid = {c.correlation_id: c for c in BreakglassCase.objects.all()}
    rows = []
    seen: set[str] = set()
    for f in flows:
        case = by_cid.get(f["correlation_id"])
        timed_out = bool(case and case.expires_at and case.expires_at <= dj_tz.now())
        if case and case.status == CaseStatus.OPEN and (f.get("expired") or timed_out):
            case.status = CaseStatus.EXPIRED
            case.save(update_fields=["status"])
        rows.append({"flow": f, "case": case, "status": (case.status if case else ("expired" if f.get("expired") else "open"))})
        seen.add(f["correlation_id"])
    # Failed-closed attempts never reach the chain as a release; show them from the ledger.
    for case in BreakglassCase.objects.exclude(correlation_id__in=seen):
        rows.append({"flow": None, "case": case, "status": case.status})
    ctx.update({"rows": rows, "store_error": store_error})
    return render(request, "admin_audit/cases.html", ctx)


# --- Federation & key custody --------------------------------------------------------


@role_required(Role.ADMIN)
def federation(request: Any) -> HttpResponse:
    ctx = _base_ctx("Federation & key custody")
    statuses = services.federation_status()
    processes = [
        {"name": s.name, "url": s.url, "ok": s.ok, "detail": s.detail, "holds": _PROCESS_HOLDS.get(s.name, "")}
        for s in statuses
    ]
    counts, store_error = _store(store_reader.table_counts, default={})
    facilities, _ = _store(store_reader.facilities, default=[])
    authorities, _ = _store(store_reader.authorities, default=[])
    records, _ = _store(store_reader.record_summaries, 50, default=[])
    lifecycle, _ = _store(store_reader.lifecycle_states, default=[])
    ctx.update(
        {
            "processes": processes,
            "store_ok": store_error is None,
            "store_error": store_error,
            "counts": counts,
            "facilities": facilities,
            "authorities": authorities,
            "records": records,
            "lifecycle": lifecycle,
            "holds_store": _PROCESS_HOLDS["store"],
        }
    )
    return render(request, "admin_audit/federation.html", ctx)


# --- Registrations (kept from the ADR-0021 shell) ------------------------------------


@role_required(Role.ADMIN)
def registrations(request: Any) -> HttpResponse:
    ctx = _base_ctx("Registrations")
    if request.method == "POST" and "approve" in request.POST:
        try:
            stubs.issue_credential(int(request.POST["approve"]))
        except stubs.NotWiredYet as exc:
            ctx["notice"] = str(exc)
    ctx["pending"] = RegistrationRequest.objects.filter(status=RequestStatus.PENDING).order_by("-created_at")
    ctx["decided"] = RegistrationRequest.objects.exclude(status=RequestStatus.PENDING).order_by("-created_at")[:20]
    return render(request, "admin_audit/registrations.html", ctx)
