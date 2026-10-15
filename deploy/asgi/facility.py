"""ASGI factory for a facility node process (P4-3, C14).

Environment:
    FACILITY_ID: This facility's identifier, e.g. ``"facility-a"``.
    DATABASE_URL: DSN for the shared store.
    AUDIT_SERVICE_URL: Base URL of the standalone Audit Service, e.g.
        ``"http://audit:8020"``. Required (review F19): a facility with no
        audit sink would release records with nothing logged. The
        emergency-expiry timer's transition events are logged through it too
        (ADR-0035).
    FEDERATION_ROOT_CERT: Path to the federation root certificate (PEM).
    FACILITY_CA_CERTS_DIR: Directory of cross-certified facility CA
        certificates, one ``<facility_id>.crt`` (PEM) per facility.
    REVOKED_CLINICIAN_SERIALS: Optional comma-separated decimal serial
        numbers of revoked clinician certificates.
    SERVICE_KEY_FILE / SERVICE_CERT_FILE: This facility's root-issued
        identity (id ``FACILITY_ID``); it signs every call it makes and callers
        must name it as recipient (ADR-0066).
    AUTHORITY_URLS: Comma-separated ``authority_id=url`` pairs; the forced
        rotation at expiry fetches authoring keys there (ADR-0069).
    CUSTODIAN_URL: Where the rotation hands the new share 1 (share 3 goes to
        ``AUDIT_SERVICE_URL``).
    EMERGENCY_DURATION_SECONDS: Default break-glass time-box length in
        seconds (ARCHITECTURE.md §7 "Configuration": short for demos,
        realistic for the paper). Defaults to 14400 (4 hours, an emergency
        encounter; ADR-0056). The demo paths set 120. A caller may
        request a shorter window, never a longer one (review F6).

Break-glass trust anchors come from this configuration, never from the
request (review F1): bootstrap writes the root and facility CA certificates
before the facilities start, and startup fails if they are missing.
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from api.audit_client import _tls_verify, make_lifecycle_audit_logger
from api.hospital import AUDIT_SERVICE_ID, FacilityTrust, create_hospital_app
from api.repository import PostgresStorageRepository
from api.rotation import http_rotation_ports
from api.service_auth import SignedRequestAuth, load_service_identity, signed_client
from crypto_core import certificate_from_pem, generate_ec_keypair
from fastapi import FastAPI
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import ConsumedEventIds, LifecycleStateMachine

from deploy.asgi.custodian import _parse_pairs

_DEFAULT_EMERGENCY_DURATION_SECONDS = 14400.0


def load_trust() -> FacilityTrust:
    """Read the break-glass trust anchors named by the environment (F1).

    Raises:
        RuntimeError: A variable is unset, a file is missing, or the CA
            directory holds no certificates -- the facility must not start.
    """
    root_path = os.environ.get("FEDERATION_ROOT_CERT")
    ca_dir = os.environ.get("FACILITY_CA_CERTS_DIR")
    if not root_path or not ca_dir:
        raise RuntimeError(
            "FEDERATION_ROOT_CERT and FACILITY_CA_CERTS_DIR must be set; "
            "break-glass trust anchors come from configuration (review F1)"
        )
    root_file = Path(root_path)
    if not root_file.is_file():
        raise RuntimeError(f"federation root certificate not found: {root_file}")
    ca_files = sorted(Path(ca_dir).glob("*.crt"))
    if not ca_files:
        raise RuntimeError(f"no facility CA certificates in {ca_dir}")
    revoked = os.environ.get("REVOKED_CLINICIAN_SERIALS", "")
    return FacilityTrust(
        root=certificate_from_pem(root_file.read_bytes()),
        facility_cas={
            path.stem: certificate_from_pem(path.read_bytes()) for path in ca_files
        },
        revoked_serials=frozenset(int(s) for s in revoked.split(",") if s.strip()),
    )


def app() -> FastAPI:
    """Build a facility node app from the environment."""
    facility_id = os.environ["FACILITY_ID"]
    database_url = os.environ["DATABASE_URL"]
    audit_service_url = os.environ.get("AUDIT_SERVICE_URL")
    if not audit_service_url:
        raise RuntimeError(
            "AUDIT_SERVICE_URL must be set: a facility does not release records "
            "it cannot log (review F19)"
        )
    duration = float(
        os.environ.get(
            "EMERGENCY_DURATION_SECONDS", str(_DEFAULT_EMERGENCY_DURATION_SECONDS)
        )
    )
    trust = load_trust()
    identity = load_service_identity()
    if identity.service_id != facility_id:
        raise RuntimeError(
            f"service identity is {identity.service_id!r}, not {facility_id!r}"
        )
    authorities = _parse_pairs(os.environ.get("AUTHORITY_URLS", ""))
    custodian_url = os.environ.get("CUSTODIAN_URL", "").rstrip("/")
    if not authorities or not custodian_url:
        raise RuntimeError(
            "AUTHORITY_URLS and CUSTODIAN_URL must be set: the rotation at "
            "expiry re-authors the policy and hands out new shares (ADR-0069)"
        )
    audit_auth = SignedRequestAuth(identity, {audit_service_url: AUDIT_SERVICE_ID})
    rotation_http = signed_client(
        identity,
        {
            **{url: aid for aid, url in authorities.items()},
            custodian_url: "custodian",
            audit_service_url: AUDIT_SERVICE_ID,
        },
        timeout=10.0,
        verify=_tls_verify(),
    )

    conn = psycopg.connect(database_url)
    conn.autocommit = True
    repo = PostgresStorageRepository(conn)

    # Dedicated timer-service identity (ADR-0003) -- never the clinician's
    # key, never the audit service's key. Fresh per process, matching this
    # deployment's fresh-bootstrap-every-run model (ADR-0039). The app below
    # attaches the store mirror, a compare-and-set after each audit append.
    timer_private_key, _timer_public_key = generate_ec_keypair()
    expiry_manager = EmergencyExpiryManager(
        signing_key=timer_private_key,
        timer_actor_id=f"system:hsm-timer:{facility_id}",
        default_duration_seconds=duration,
        audit_logger=make_lifecycle_audit_logger(audit_service_url, auth=audit_auth),
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
        trust=trust,
        identity=identity,
        rotation_ports=http_rotation_ports(
            rotation_http,
            authorities=authorities,
            custodian_url=custodian_url,
            audit_url=audit_service_url,
        ),
    )
