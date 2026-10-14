"""Encounter coordination, clinical notes and downtime; no keys are held here."""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta
from typing import Any
from uuid import uuid4

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST
from portal_core import notify, services
from portal_core.access import role_required
from portal_core.clinical import digest
from portal_core.services import ServiceError

from accounts.models import Role
from ledger.models import CareEpisode, DowntimeEvent, BreakglassCase, CaseStatus


@role_required(Role.CLINICIAN)
@require_POST
def federated_search(request: Any, pk: int) -> HttpResponse:
    """Authorize each record separately; never present an incomplete scan as negative."""
    from clinician.views import _discover

    case = get_object_or_404(
        BreakglassCase, pk=pk, clinician_id=request.user.profile.subject_id
    )
    term = request.POST.get("search_term", "").strip()
    context: dict[str, Any] = {
        "case": case,
        "term": term,
        "hits": [],
        "errors": [],
        "checked": 0,
    }
    deadline = case.expires_at
    if case.episode:
        if case.episode.closed_at:
            return HttpResponse("Care episode is closed", status=403)
        deadline = min(deadline, case.episode.expires_at) if deadline else None
    if (
        not term
        or not deadline
        or deadline <= timezone.now()
        or case.status != CaseStatus.OPEN
    ):
        return HttpResponse(
            "A term and a live emergency window are required", status=403
        )
    try:
        records = _discover(request.user.profile.home_facility_id, case.patient_id)
    except ServiceError as exc:
        context["errors"].append(f"Discovery unavailable: {exc.detail}")
        records = []
    for record in records:
        rid = record["record_id"]
        clinical = record.get("clinical")
        if not clinical or clinical.get("sensitivity", "general") != "general":
            context["errors"].append(
                f"{rid}: restricted or unclassified; select this record separately and explain its necessity."
            )
            continue
        remaining = (deadline - timezone.now()).total_seconds()
        if remaining <= 0:
            context["errors"].append(
                "The window expired before all records could be checked."
            )
            break
        correlation = f"search-{uuid4()}"
        try:
            opened = services.custodian_breakglass(
                case.clinician_id,
                patient_id=case.patient_id,
                record_id=rid,
                reason_code=case.reason_code,
                correlation_id=correlation,
                facility_id=record["facility_id"],
                emergency_duration_seconds=remaining,
                justification=case.justification,
            )
            # Payload may be returned by the existing agent; do not render or persist it.
            opened.pop("plaintext_b64", None)
            opened_case = BreakglassCase.objects.create(
                correlation_id=opened["correlation_id"],
                record_id=rid,
                patient_id=case.patient_id,
                clinician_id=case.clinician_id,
                facility_id=opened["facility_id"],
                reason_code=case.reason_code,
                justification=case.justification,
                episode=case.episode,
                assertion_id=opened["assertion_id"],
                shares=opened["shares_presented"],
                opened_at=parse_datetime(opened["opened_at"]),
                expires_at=parse_datetime(opened["expires_at"]),
            )
            notify.notify_breakglass(
                patient_id=case.patient_id,
                record_id=rid,
                clinician_id=case.clinician_id,
                facility_id=opened["facility_id"],
                correlation_id=opened["correlation_id"],
                reason_code=case.reason_code,
            )
            hits = services.facility_emergency_search(
                opened["facility_id"], rid, term, case.clinician_id
            )
            context["checked"] += 1
            if rid in hits:
                context["hits"].append({"case": opened_case, "record": record})
        except ServiceError as exc:
            context["errors"].append(f"{rid}: {exc.service}: {exc.detail}")
    response = render(request, "clinician/federated_search.html", context)
    response["Cache-Control"] = "no-store"
    return response


@role_required(Role.CLINICIAN)
def encounter(request: Any) -> HttpResponse:
    """Create an unidentified encounter or resolve it using a logged selection."""
    clinician = request.user.profile.subject_id
    context: dict[str, Any] = {
        "episodes": CareEpisode.objects.filter(clinician_id=clinician).order_by(
            "-created_at"
        )[:30]
    }
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "temporary":
            episode = CareEpisode.objects.create(
                clinician_id=clinician,
                facility_id=request.user.profile.home_facility_id,
                temporary_identifier=f"TEMP-{uuid4().hex[:12].upper()}",
                label="Unidentified emergency arrival",
                expires_at=timezone.now()
                + timedelta(seconds=settings.EMERGENCY_DURATION_SECONDS),
            )
            request.session["clinician.episode"] = str(episode.pk)
            request.session.pop("clinician.identified", None)
            context["notice"] = (
                f"Use wristband / paper identifier {episode.temporary_identifier}. No historical patient has been selected."
            )
        elif action in ("resolve", "close"):
            episode = get_object_or_404(
                CareEpisode,
                pk=request.POST.get("episode_id"),
                clinician_id=clinician,
                closed_at__isnull=True,
            )
            ident = request.session.get("clinician.identified") or {}
            evidence = request.POST.get("evidence", "").strip()
            if action == "resolve" and (
                episode.patient_id
                or episode.expires_at <= timezone.now()
                or not ident.get("patient_id")
                or len(evidence) < 20
            ):
                context["error"] = (
                    "First select a patient through directory lookup and record how identity was confirmed (at least 20 characters)."
                )
            else:
                seq = notify.append_audit(
                    event_type=f"encounter.{action}",
                    event_data={
                        "episode_id": str(episode.pk),
                        "patient_id": (
                            ident.get("patient_id")
                            if action == "resolve"
                            else episode.patient_id
                        ),
                        "clinician_id": clinician,
                        "evidence_digest": digest(evidence),
                    },
                    actor_id=clinician,
                    correlation_id=f"episode-{episode.pk}",
                )
                if seq is None:
                    context["error"] = (
                        "Audit unavailable; identity binding / closure was not changed. Use the downtime procedure."
                    )
                else:
                    if action == "resolve":
                        episode.patient_id = ident["patient_id"]
                        episode.identity_evidence = evidence
                        request.session["clinician.episode"] = str(episode.pk)
                    else:
                        episode.closed_at = timezone.now()
                        if request.session.get("clinician.episode") == str(episode.pk):
                            request.session.pop("clinician.identified", None)
                            request.session.pop("clinician.episode", None)
                    episode.save()
                    context["notice"] = (
                        "Encounter updated. Historical records were not reassigned or merged."
                    )
    return render(request, "clinician/encounter.html", context)


@role_required(Role.CLINICIAN)
def downtime(request: Any) -> HttpResponse:
    """Capture the use of local procedures without pretending to release records."""
    context: dict[str, Any] = {}
    if request.method == "POST":
        procedure = request.POST.get("procedure")
        if procedure not in dict(DowntimeEvent._meta.get_field("procedure").choices):
            return HttpResponse("Choose a downtime procedure", status=400)
        item = DowntimeEvent.objects.create(
            clinician_id=request.user.profile.subject_id,
            episode_id=request.session.get("clinician.episode", ""),
            procedure=procedure,
        )
        context["notice"] = (
            f"Downtime event {item.pk} queued for recovery review. No encrypted record was released."
        )
    return render(request, "clinician/downtime.html", context)


@role_required(Role.CLINICIAN)
def note(request: Any, pk: int) -> HttpResponse:
    """Write a new encrypted, attributed note after backend emergency validation."""
    case = get_object_or_404(
        BreakglassCase, pk=pk, clinician_id=request.user.profile.subject_id
    )
    context: dict[str, Any] = {"case": case, "today": timezone.now().date().isoformat()}
    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        content = request.POST.get("content", "").strip()
        try:
            clinical_date = date.fromisoformat(request.POST.get("clinical_date", ""))
            if not title or not content or clinical_date > timezone.now().date():
                raise ValueError(
                    "A title, note and non-future clinical date are required"
                )
            if (
                case.status != CaseStatus.OPEN
                or not case.expires_at
                or case.expires_at <= timezone.now()
            ):
                raise ValueError("The emergency window has closed")
            clinical = {
                "title": title,
                "clinical_date": clinical_date.isoformat(),
                "record_type": "clinical_note",
                "episode_id": str(case.episode_id or case.pk),
                "care_team_consent": True,
                "sensitivity": request.POST.get("sensitivity", "general"),
            }
            policy = {
                "node_type": "or",
                "children": [
                    {
                        "node_type": "leaf",
                        "authority_id": "authority-med",
                        "attribute": {"name": "role", "value": role},
                    }
                    for role in ("physician", "emergency-physician")
                ],
            }
            services._request(
                "custodian",
                "POST",
                f"{settings.CUSTODIAN_URL}/subjects/{case.clinician_id}/records",
                json={
                    "patient_id": case.patient_id,
                    "facility_id": case.facility_id,
                    "content_b64": base64.b64encode(
                        json.dumps({"note": content}).encode()
                    ).decode(),
                    "content_type": "application/json",
                    "clinical_policy": policy,
                    "clinical": clinical,
                    "emergency": {
                        "patient_id": case.patient_id,
                        "record_id": case.record_id,
                        "facility_id": case.facility_id,
                        "reason_code": case.reason_code,
                        "justification": case.justification,
                        "sensitive_justification": case.sensitive_justification,
                    },
                },
            )
        except (ValueError, ServiceError) as exc:
            context["error"] = str(exc)
        else:
            return redirect("clinician:case_detail", pk=case.pk)
    return render(request, "clinician/note.html", context)
