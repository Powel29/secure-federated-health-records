"""Admin / audit portal (P4-12). Read-only over the store; review registrations.

This is the one portal that shows *real* data now -- it reads the P0-8 store
through the read-only `store` alias (audit log, records, lifecycle). It can view
pending registration requests, but *approving* one only reaches the
issue_credential stub: issuance is the authority's job (P2-2), never the portal's.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from accounts.models import RegistrationRequest, RequestStatus
from portal_core import store_reader, stubs


@login_required
def home(request):
    ctx: dict = {"notice": None}

    if request.method == "POST" and "approve" in request.POST:
        try:
            stubs.issue_credential(int(request.POST["approve"]))
        except stubs.NotWiredYet as exc:
            ctx["notice"] = str(exc)

    # Real, read-only reads of the store. Empty until ingest exists; a connection
    # error just means the store DB is not reachable in this environment.
    try:
        ctx["audit"] = store_reader.recent_audit()
        ctx["records"] = store_reader.record_summaries()
        ctx["lifecycle"] = store_reader.lifecycle_states()
    except Exception as exc:  # noqa: BLE001 - display-only, never fatal
        ctx["store_error"] = str(exc)

    ctx["pending"] = RegistrationRequest.objects.filter(
        status=RequestStatus.PENDING
    ).order_by("-created_at")
    return render(request, "admin_audit/home.html", ctx)
