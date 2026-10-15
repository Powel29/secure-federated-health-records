"""ASGI factory for an attribute authority process (P4-3, C14/C6).

Environment:
    AUTHORITY_ID: This authority's identifier, e.g. ``"authority-med"``.
    OWNED_ATTRIBUTES: Comma-separated attribute names this authority may
        issue, e.g. ``"role"`` or ``"specialty,facility,owner"``
        (ADR-0019 namespace assignment).
    SERVICE_KEY_FILE / SERVICE_CERT_FILE: This service's root-issued
        identity, whose id must be ``AUTHORITY_ID`` (ADR-0066).
    FEDERATION_ROOT_CERT: The federation root callers must chain to. Only a
        signed request from a facility, the custodian or bootstrap gets an
        authoring key (replacing the review F14 address allowlist).
"""

from __future__ import annotations

import os

from api.authority_service import create_authority_app
from api.service_auth import load_service_identity, load_trusted_root
from fastapi import FastAPI


def app() -> FastAPI:
    """Build the Attribute Authority Service app from the environment."""
    authority_id = os.environ["AUTHORITY_ID"]
    owned_attribute_names = frozenset(
        name.strip()
        for name in os.environ["OWNED_ATTRIBUTES"].split(",")
        if name.strip()
    )
    identity = load_service_identity()
    if identity.service_id != authority_id:
        raise RuntimeError(
            f"service identity is {identity.service_id!r}, not {authority_id!r}"
        )
    return create_authority_app(
        authority_id, owned_attribute_names, service_root=load_trusted_root()
    )
