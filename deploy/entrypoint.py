"""Single process entrypoint, dispatching on ``SERVICE_ROLE`` (P4-3).

Used identically by ``deploy/run_local.py`` (Path A, as a subprocess) and by
``deploy/Dockerfile``'s ``ENTRYPOINT`` (Path B, one container per service):
there is exactly one way a service process starts, regardless of which
deployment path launched it.

Environment:
    SERVICE_ROLE: One of ``"facility"``, ``"authority"``, ``"audit"``,
        ``"custodian"`` -- selects which ``deploy.asgi`` factory to run.
    PORT: TCP port to bind (default ``8000``).
    HOST: Interface to bind (default ``127.0.0.1``; Compose sets ``0.0.0.0``
        explicitly because it binds inside the bridge network -- review F16).

    Every other environment variable is role-specific -- see the matching
    ``deploy.asgi.<role>`` module's docstring.
"""

from __future__ import annotations

import os
import sys

import uvicorn

from deploy.config import configure_transport

_FACTORIES = {
    "facility": "deploy.asgi.facility:app",
    "authority": "deploy.asgi.authority:app",
    "audit": "deploy.asgi.audit:app",
    "custodian": "deploy.asgi.custodian:app",
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
    host = os.environ.get("HOST", "127.0.0.1")
    configure_transport(
        os.environ.get("FACILITY_ID") or os.environ.get("AUTHORITY_ID") or role
    )

    tls_enabled = os.environ.get("TLS_ENABLED", "").lower() in {"1", "true", "yes"}
    ssl_certfile = os.environ.get("SSL_CERTFILE")
    ssl_keyfile = os.environ.get("SSL_KEYFILE")

    if tls_enabled and not (ssl_certfile and ssl_keyfile):
        print(
            "TLS_ENABLED requires SSL_CERTFILE and SSL_KEYFILE",
            file=sys.stderr,
        )
        return 2

    uvicorn.run(
        "deploy.asgi:app",
        host=host,
        port=port,
        factory=True,
        log_level="info",
        ssl_certfile=ssl_certfile if tls_enabled else None,
        ssl_keyfile=ssl_keyfile if tls_enabled else None,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
