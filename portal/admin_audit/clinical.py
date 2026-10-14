"""Audited clinical oversight and verified contact relationships."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from portal_core import notify, services, store_reader
from portal_core.access import role_required
from portal_core.clinical import digest

from accounts.models import PatientDirectory, PatientRepresentative, Role
from ledger.models import BreakglassCase, DowntimeEvent


@role_required(Role.ADMIN)
def review(request: Any, pk: int) -> HttpResponse:
    """Adjudicate only after the decision has been committed to the audit chain."""
    with transaction.atomic():
        case = get_object_or_404(BreakglassCase.objects.select_for_update(), pk=pk)
        context: dict[str, Any] = {"case": case}
        try:
            entries = store_reader.audit_by_correlation(case.correlation_id)
            import json

            data = [
                (
                    json.loads(e["event_data"])
                    if isinstance(e.get("event_data"), str)
                    else e.get("event_data", {})
                )
                for e in entries
            ]
            context["justification_verified"] = services.audit_verify().get(
                "verified"
            ) is True and any(
                d.get("justification_digest") == digest(case.justification)
                and d.get("sensitive_justification_digest")
                == digest(case.sensitive_justification)
                for d in data
            )
        except Exception:  # An unavailable chain cannot establish integrity.
            context["justification_verified"] = False
        if request.method == "POST":
            outcome = request.POST.get("outcome")
            note = request.POST.get("note", "").strip()
            reviewer = request.user.profile.subject_id
            if case.review_status != "pending":
                context["error"] = "This case has already been adjudicated."
            elif reviewer == case.clinician_id:
                context["error"] = "A clinician cannot adjudicate their own access."
            elif (
                outcome not in ("appropriate", "inappropriate", "escalated")
                or len(note) < 20
            ):
                context["error"] = (
                    "Select an outcome and record the review rationale (at least 20 characters)."
                )
            elif outcome == "appropriate" and not context["justification_verified"]:
                context["error"] = (
                    "Justification does not match a chain commitment. Escalate for investigation."
                )
            else:
                seq = notify.append_audit(
                    event_type="breakglass.adjudicated",
                    event_data={
                        "case_id": case.pk,
                        "patient_id": case.patient_id,
                        "record_id": case.record_id,
                        "reviewer_id": reviewer,
                        "outcome": outcome,
                        "review_digest": digest(note),
                        "justification_verified": context["justification_verified"],
                    },
                    actor_id=reviewer,
                    correlation_id=case.correlation_id,
                )
                if seq is None:
                    context["error"] = "Audit unavailable; the case remains pending."
                else:
                    case.review_status, case.review_note = outcome, note
                    case.reviewed_by, case.reviewed_at = reviewer, timezone.now()
                    case.review_audit_seq = seq
                    case.save()
                    return redirect("admin_audit:cases")
    return render(request, "admin_audit/review.html", context)


@role_required(Role.ADMIN)
def downtime(request: Any) -> HttpResponse:
    context: dict[str, Any] = {}
    if request.method == "POST":
        with transaction.atomic():
            item = get_object_or_404(
                DowntimeEvent.objects.select_for_update(),
                pk=request.POST.get("event_id"),
            )
            if item.reconciled_at is None:
                seq = notify.append_audit(
                    event_type="downtime.reconciled",
                    event_data={
                        "event_id": str(item.pk),
                        "clinician_id": item.clinician_id,
                        "episode_id": item.episode_id,
                        "procedure": item.procedure,
                        "occurred_at": item.created_at.isoformat(),
                        "reviewer_id": request.user.profile.subject_id,
                    },
                    actor_id=request.user.profile.subject_id,
                    correlation_id=f"downtime-{item.pk}",
                )
                if seq is None:
                    context["error"] = "Audit still unavailable; event remains queued."
                else:
                    item.audit_seq, item.reconciled_at = seq, timezone.now()
                    item.save()
    context["events"] = DowntimeEvent.objects.order_by("-created_at")[:100]
    return render(request, "admin_audit/downtime.html", context)


@role_required(Role.ADMIN)
def representatives(request: Any) -> HttpResponse:
    context: dict[str, Any] = {}
    if request.method == "POST" and request.POST.get("action") == "revoke":
        with transaction.atomic():
            representative = get_object_or_404(
                PatientRepresentative.objects.select_for_update(),
                pk=request.POST.get("representative_pk"),
            )
            if representative.revoked_at is None:
                seq = notify.append_audit(
                    event_type="patient.representative_revoked",
                    event_data={
                        "patient_id": representative.patient.subject_id,
                        "representative_id": representative.representative_id,
                    },
                    actor_id=request.user.profile.subject_id,
                    correlation_id=f"representative-{representative.pk}-revoke",
                )
                if seq is None:
                    context["error"] = "Audit unavailable; revocation was not recorded"
                else:
                    representative.revoked_at = timezone.now()
                    representative.receive_notifications = False
                    representative.save(
                        update_fields=["revoked_at", "receive_notifications"]
                    )
        context["representatives"] = PatientRepresentative.objects.select_related(
            "patient"
        ).all()
        return render(request, "admin_audit/representatives.html", context)
    if request.method == "POST":
        patient = get_object_or_404(
            PatientDirectory, subject_id=request.POST.get("patient_id")
        )
        representative_id = request.POST.get("representative_id", "").strip()
        relation = request.POST.get("relationship")
        reference = request.POST.get("verification_reference", "").strip()
        try:
            expires_at = datetime.fromisoformat(request.POST.get("expires_at", ""))
            if timezone.is_naive(expires_at):
                expires_at = timezone.make_aware(expires_at)
            if (
                expires_at <= timezone.now()
                or not representative_id
                or not reference
                or relation not in ("guardian", "parent", "next_of_kin")
            ):
                raise ValueError(
                    "Provide a verified relationship, representative, evidence reference and future expiry"
                )
            seq = notify.append_audit(
                event_type="patient.representative_verified",
                event_data={
                    "patient_id": patient.subject_id,
                    "representative_id": representative_id,
                    "relationship": relation,
                    "evidence_digest": digest(reference),
                    "expires_at": expires_at.isoformat(),
                },
                actor_id=request.user.profile.subject_id,
                correlation_id=f"representative-{patient.pk}-{representative_id}",
            )
            if seq is None:
                raise ValueError("Audit unavailable; relationship was not saved")
            PatientRepresentative.objects.update_or_create(
                patient=patient,
                representative_id=representative_id,
                defaults={
                    "display_name": request.POST.get("display_name", "").strip(),
                    "relationship": relation,
                    "verification_reference": reference,
                    "verified_by": request.user.profile.subject_id,
                    "expires_at": expires_at,
                    "receive_notifications": request.POST.get("receive_notifications")
                    == "yes",
                    "revoked_at": None,
                },
            )
        except ValueError as exc:
            context["error"] = str(exc)
    context["representatives"] = PatientRepresentative.objects.select_related(
        "patient"
    ).all()
    return render(request, "admin_audit/representatives.html", context)
