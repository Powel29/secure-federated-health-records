"""ASGI factory for a facility node process (P4-3, C14).

Environment:
    FACILITY_ID: This facility's identifier, e.g. ``"facility-a"``.
    DATABASE_URL: DSN for the shared store.
    AUDIT_SERVICE_URL: Base URL of the standalone Audit Service, e.g.
        ``"http://audit:8020"``. When set, the emergency-expiry timer's
        transition events are logged through it -- closing the seam
        ``lifecycle.expiry.EmergencyExpiryManager`` documents as deferred to
        "Phase 4 API integration (P4-2)" (ADR-0035). When unset, expiry
        still runs correctly; its transitions just do not enter the hash
        chain (the same documented limitation, unresolved -- useful for a
        facility running standalone against no audit service at all).
    EMERGENCY_DURATION_SECONDS: Default break-glass time-box length in
        seconds (ARCHITECTURE.md §7 "Configuration": short for demos,
        realistic for the paper). Defaults to 900 (15 minutes).

This module deliberately holds no PKI material of its own: ``create_hospital_app``'s
routes take certificates and keys as request data (P4-1 design -- see
``api.hospital``), so a facility node has nothing to bootstrap here beyond a
database connection and its own emergency-expiry timer identity.
"""

from __future__ import annotations

import os

import psycopg
from api.audit_client import make_lifecycle_audit_logger
from api.hospital import create_hospital_app
from api.repository import PostgresStorageRepository
from crypto_core import generate_ec_keypair
from fastapi import FastAPI
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import ConsumedEventIds, LifecycleStateMachine

_DEFAULT_EMERGENCY_DURATION_SECONDS = 900.0


def app() -> FastAPI:
    """Build a facility node app from the environment."""
    facility_id = os.environ["FACILITY_ID"]
    database_url = os.environ["DATABASE_URL"]
    audit_service_url = os.environ.get("AUDIT_SERVICE_URL")
    duration = float(
        os.environ.get(
            "EMERGENCY_DURATION_SECONDS", str(_DEFAULT_EMERGENCY_DURATION_SECONDS)
        )
    )

    conn = psycopg.connect(database_url)
    conn.autocommit = True
    repo = PostgresStorageRepository(conn)

    # Dedicated timer-service identity (ADR-0003) -- never the clinician's
    # key, never the audit service's key. Fresh per process, matching this
    # deployment's fresh-bootstrap-every-run model (ADR-0039).
    timer_private_key, _timer_public_key = generate_ec_keypair()
    audit_logger = (
        make_lifecycle_audit_logger(audit_service_url) if audit_service_url else None
    )
    expiry_manager = EmergencyExpiryManager(
        signing_key=timer_private_key,
        timer_actor_id=f"system:hsm-timer:{facility_id}",
        default_duration_seconds=duration,
        audit_logger=audit_logger,
        # Transition-event ids persist in the store, so a restart cannot
        # replay a consumed expiry event (review F22).
        state_machine=LifecycleStateMachine(ConsumedEventIds(backend=repo)),
    )
    expiry_manager.start_monitor()

    return create_hospital_app(
        facility_id=facility_id,
        repository=repo,
        expiry_manager=expiry_manager,
        audit_service_url=audit_service_url,
    )
