"""ASGI factory for an attribute authority process (P4-3, C14/C6).

Environment:
    AUTHORITY_ID: This authority's identifier, e.g. ``"authority-med"``.
    OWNED_ATTRIBUTES: Comma-separated attribute names this authority may
        issue, e.g. ``"role"`` or ``"specialty,facility,owner"``
        (ADR-0019 namespace assignment).
    AUTHORING_CALLERS: Optional comma-separated addresses or hostnames
        allowed to fetch authoring keys (review F14 interim). Defaults to
        loopback; Compose names its custodian and bootstrap containers.
"""

from __future__ import annotations

import os

from api.authority_service import DEFAULT_AUTHORING_CALLERS, create_authority_app
from fastapi import FastAPI


def app() -> FastAPI:
    """Build the Attribute Authority Service app from the environment."""
    authority_id = os.environ["AUTHORITY_ID"]
    owned_attribute_names = frozenset(
        name.strip()
        for name in os.environ["OWNED_ATTRIBUTES"].split(",")
        if name.strip()
    )
    callers = os.environ.get("AUTHORING_CALLERS")
    authoring_callers = (
        frozenset(c.strip() for c in callers.split(",") if c.strip())
        if callers
        else DEFAULT_AUTHORING_CALLERS
    )
    return create_authority_app(
        authority_id, owned_attribute_names, authoring_callers=authoring_callers
    )
