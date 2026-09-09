"""Single process entrypoint, dispatching on ``SERVICE_ROLE`` (P4-3).

Used identically by ``deploy/run_local.py`` (Path A, as a subprocess) and by
``deploy/Dockerfile``'s ``ENTRYPOINT`` (Path B, one container per service):
there is exactly one way a service process starts, regardless of which
deployment path launched it.

Environment:
    SERVICE_ROLE: One of ``"facility"``, ``"authority"``, ``"audit"`` --
        selects which ``deploy.asgi`` factory to run.
    PORT: TCP port to bind (default ``8000``).
    HOST: Interface to bind (default ``0.0.0.0``).

    Every other environment variable is role-specific -- see the matching
    ``deploy.asgi.<role>`` module's docstring.
"""

from __future__ import annotations

import os
import sys

import uvicorn

_FACTORIES = {
    "facility": "deploy.asgi.facility:app",
    "authority": "deploy.asgi.authority:app",
    "audit": "deploy.asgi.audit:app",
}


def main() -> int:
    """Read ``SERVICE_ROLE`` and run the matching ASGI factory under uvicorn."""
    role = os.environ.get("SERVICE_ROLE")
    if role not in _FACTORIES:
        print(
            f"SERVICE_ROLE must be one of {sorted(_FACTORIES)}, got {role!r}",
            file=sys.stderr,
        )
        return 2

    port = int(os.environ.get("PORT", "8000"))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run(_FACTORIES[role], host=host, port=port, factory=True, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
