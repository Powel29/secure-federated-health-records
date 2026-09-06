"""Patient portal shell (P4-7). Manage access + view own records.

Upload and record-viewing are stubbed until the ingest/crypto path exists; the
page works, the actions raise NotWiredYet rather than faking success.
"""

from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from portal_core import stubs


@login_required
def home(request):
    notice = None
    if request.method == "POST" and "upload" in request.POST:
        try:
            stubs.ingest_upload(
                request.user.profile.subject_id,
                request.POST.get("filename", ""),
                b"",
            )
        except stubs.NotWiredYet as exc:
            notice = str(exc)
    return render(request, "patient/home.html", {"notice": notice})
