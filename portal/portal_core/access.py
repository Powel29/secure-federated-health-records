"""Role gating for portal views (identity only, ADR-0014).

``@role_required(Role.PATIENT)`` answers *who is asking* and routes a login
with the wrong (or no) profile away. It never answers *may this be decrypted*
-- that stays with keys and the threshold gate.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

from accounts.models import Profile, RegistrationRequest, RequestStatus, Role

_HOME = {
    Role.PATIENT: "patient:home",
    Role.CLINICIAN: "clinician:home",
    Role.ADMIN: "admin_audit:home",
}


def profile_of(user: Any) -> Profile | None:
    return getattr(user, "profile", None)


def is_issued(user: Any) -> bool:
    """No registration of this login is still pending or was denied (F17).

    Seeded and administrator-created accounts are issued by construction; a
    self-registered login has a PENDING request until an authority issues
    its credential, and reaches no portal (and so no custodian call) before.
    """
    return not RegistrationRequest.objects.filter(
        user=user, status__in=(RequestStatus.PENDING, RequestStatus.DENIED)
    ).exists()


def role_required(role: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @login_required
        @wraps(view)
        def wrapped(request: Any, *args: Any, **kwargs: Any) -> Any:
            profile = profile_of(request.user)
            if profile is None:
                # A superuser has no profile; the admin/audit portal is the
                # only sensible destination for such a login.
                if request.user.is_superuser and role == Role.ADMIN:
                    return view(request, *args, **kwargs)
                return redirect("home")
            if profile.role != role:
                return redirect(_HOME.get(profile.role, "home"))
            if not is_issued(request.user):
                return redirect("home")  # "pending approval" page
            return view(request, *args, **kwargs)

        return wrapped

    return decorator
