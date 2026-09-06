"""Clinician portal shell (P4-8). Request access, search, declare break-glass.

All actions are stubbed until their backends exist (lifecycle/breakglass). The
clinician's own registration status is shown so they can see they hold no issued
credential yet -- which is why they can open nothing.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from portal_core import stubs


@login_required
def home(request):
    notice = None
    if request.method == "POST":
        patient_id = request.POST.get("patient_id", "")
        clinician_id = request.user.profile.subject_id
        try:
            if "request_access" in request.POST:
                stubs.request_access(clinician_id, patient_id)
            elif "breakglass" in request.POST:
                stubs.declare_breakglass(
                    clinician_id, patient_id, request.POST.get("reason", "")
                )
        except stubs.NotWiredYet as exc:
            notice = str(exc)
    return render(request, "clinician/home.html", {"notice": notice})
