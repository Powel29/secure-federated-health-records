"""ASGI factory for the audit service process (P4-3, C14/C10/C11).

Environment:
    DATABASE_URL: DSN for the shared store.
    AUDIT_ACTOR_ID: Identity this service signs entries as (default
        ``"audit-service"``).
    SERVICE_KEY_FILE / SERVICE_CERT_FILE: This service's root-issued
        identity; callers' requests must name it as recipient (ADR-0066).
    FEDERATION_ROOT_CERT: The federation root; callers' service certificates
        and clinicians' certificate chains are checked against it.
    FACILITY_CA_CERTS_DIR: The facility CA certificates clinician
        certificates chain through: share 3 is released only against an
        emergency assertion validated here (ADR-0067).
    REVOKED_CLINICIAN_SERIALS: Optional, as for a facility.
"""

from __future__ import annotations

import os

import psycopg
from api.audit_service import create_audit_app
from api.service_auth import load_service_identity
from fastapi import FastAPI

from deploy.asgi.facility import load_trust


def app() -> FastAPI:
    """Build the Audit Service app from the environment.

    Opens its own dedicated connection to the shared store -- this process
    is the chain's sole writer, and ``create_audit_app`` switches that
    connection to autocommit so every append is immediately durable
    (ARCHITECTURE.md §7: "if chain verification fails at boot, nothing else
    starts").
    """
    database_url = os.environ["DATABASE_URL"]
    actor_id = os.environ.get("AUDIT_ACTOR_ID", "audit-service")
    identity = load_service_identity()
    trust = load_trust()
    conn = psycopg.connect(database_url)
    return create_audit_app(
        conn,
        actor_id=actor_id,
        service_root=trust.root,
        trust=trust,
        service_id=identity.service_id,
    )
