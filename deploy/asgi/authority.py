"""ASGI factory for an attribute authority process (P4-3, C14/C6).

Environment:
    AUTHORITY_ID: This authority's identifier, e.g. ``"authority-med"``.
    OWNED_ATTRIBUTES: Comma-separated attribute names this authority may
        issue, e.g. ``"role"`` or ``"specialty,facility,owner"``
        (ADR-0019 namespace assignment).
    SERVICE_KEY_FILE / SERVICE_CERT_FILE: This service's root-issued
        identity, whose id must be ``AUTHORITY_ID`` (ADR-0066). It also signs
        the share-key statement custodians and facilities seal share 2 to
        (ADR-0079, ADR-0089).
    FEDERATION_ROOT_CERT: The federation root callers must chain to. Only a
        signed request from a facility, the custodian or bootstrap gets an
        authoring key (replacing the review F14 address allowlist).
    FACILITY_CA_CERTS_DIR: The facility CAs that certify patients and
        clinicians. A credential's key is released only to a request its
        subject signed under one of them (ADR-0082, review F15), and share 2
        only against an emergency assertion that chains through one of them
        (ADR-0089).
    REVOKED_CLINICIAN_SERIALS: Optional, as for a facility.
    DATABASE_URL: Optional DSN for the shared store. When set, a facility may
        replace share 2 while the store shows the record ``expired`` or
        ``revoked`` (its rotation, ADR-0069 / ADR-0080); without it share 2
        is never replaced. Only the lifecycle state is read.
"""

from __future__ import annotations

import os

from api.authority_service import SubjectTrust, create_authority_app
from api.service_auth import load_service_identity
from contracts.enums import LifecycleState
from fastapi import FastAPI

from deploy.asgi.facility import load_trust


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
    trust = load_trust()

    state_loader = None
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        import psycopg
        from storage.repositories import get_lifecycle_state

        conn = psycopg.connect(database_url)
        conn.autocommit = True

        def state_loader(record_id: str) -> LifecycleState | None:  # type: ignore[no-redef]
            row = get_lifecycle_state(conn, record_id)
            return LifecycleState(row["state"]) if row else None

    return create_authority_app(
        authority_id,
        owned_attribute_names,
        service_root=trust.root,
        subject_trust=SubjectTrust(
            root=trust.root,
            facility_cas=trust.facility_cas,
            revoked_serials=trust.revoked_serials,
        ),
        identity=identity,
        trust=trust,
        state_loader=state_loader,
    )
