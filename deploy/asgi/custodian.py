"""ASGI factory for the Key Custodian Service process (ADR-0043, C14).

Environment:
    AUTHORITY_URLS: Comma-separated ``authority_id=url`` pairs, e.g.
        ``"authority-med=http://127.0.0.1:8010,authority-net=http://127.0.0.1:8011"``.
    FACILITY_URLS: Comma-separated ``facility_id=url`` pairs.
    AUDIT_SERVICE_URL: Base URL of the standalone Audit Service.
    DATABASE_URL: Optional DSN for the shared store. When set, a break-glass
        result carries the decrypted record for display (the custodian reads
        the ciphertext row itself and decrypts with the DEK the PRE delivery
        package yields). When unset, break-glass still runs end to end and
        reports the recovered DEK only.
    TLS_VERIFY / CAPTURE_TLS: Same double-gated escape hatch as
        ``api.audit_client`` (ADR-0042) for the ``capture-tls`` profile.
    SERVICE_KEY_FILE / SERVICE_CERT_FILE / FEDERATION_ROOT_CERT: The
        custodian's root-issued identity, which signs every call it makes,
        and the root its callers must chain to (ADR-0066). With
        ``DATABASE_URL`` set, a facility may replace share 1 while the store
        shows the record ``expired`` (ADR-0069).
"""

from __future__ import annotations

import os

import httpx
from api.audit_client import _tls_verify
from api.custodian_service import (
    DEFAULT_TIMEOUT_SECONDS,
    CustodianEndpoints,
    create_custodian_app,
)
from api.service_auth import load_service_identity, load_trusted_root
from contracts import Record
from contracts.enums import LifecycleState
from fastapi import FastAPI


def _parse_pairs(raw: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        key, _, value = item.partition("=")
        if not key or not value:
            raise ValueError(f"expected 'id=url', got {item!r}")
        pairs[key.strip()] = value.strip().rstrip("/")
    return pairs


def app() -> FastAPI:
    """Build the Key Custodian Service app from the environment."""
    endpoints = CustodianEndpoints(
        authorities=_parse_pairs(os.environ.get("AUTHORITY_URLS", "")),
        facilities=_parse_pairs(os.environ.get("FACILITY_URLS", "")),
        audit=os.environ.get("AUDIT_SERVICE_URL") or None,
    )

    record_loader = None
    state_loader = None
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        import psycopg
        from storage.repositories import get_lifecycle_state, get_record

        conn = psycopg.connect(database_url)
        conn.autocommit = True

        def record_loader(record_id: str) -> Record | None:  # type: ignore[no-redef]
            return get_record(conn, record_id)

        def state_loader(record_id: str) -> LifecycleState | None:  # type: ignore[no-redef]
            row = get_lifecycle_state(conn, record_id)
            return LifecycleState(row["state"]) if row else None

    return create_custodian_app(
        endpoints=endpoints,
        record_loader=record_loader,
        http_client=httpx.Client(timeout=DEFAULT_TIMEOUT_SECONDS, verify=_tls_verify()),
        identity=load_service_identity(),
        service_root=load_trusted_root(),
        state_loader=state_loader,
    )
