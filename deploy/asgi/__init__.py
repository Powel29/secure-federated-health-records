"""ASGI application factories, one module per service role (P4-3).

Each module exposes a zero-argument ``app()`` factory reading its own
configuration from the environment, so the exact same factory can be handed
to ``uvicorn --factory`` (or ``uvicorn.run(..., factory=True)``) whether the
process was launched as a local subprocess (Path A,
``deploy/run_local.py``) or as a Docker container (Path B,
``deploy/Dockerfile`` + ``deploy/entrypoint.py``).
"""

from __future__ import annotations

import importlib
import os
from uuid import uuid4

from fastapi import FastAPI


def app() -> FastAPI:
    """Wrap the selected service with a non-secret process-instance endpoint."""
    role = os.environ["SERVICE_ROLE"]
    if role not in {"authority", "audit", "facility", "custodian"}:
        raise ValueError("unknown service role")
    application = importlib.import_module(f"deploy.asgi.{role}").app()
    instance_id = str(uuid4())

    @application.get("/deployment/instance")
    def instance() -> dict[str, str]:
        return {"instance_id": instance_id}

    return application
