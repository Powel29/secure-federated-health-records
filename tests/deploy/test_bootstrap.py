"""Integration tests for the deployment bootstrap sequence (P4-3).

Exercises the bootstrap-sequence library (`deploy.bootstrap`) against real
in-process HTTP servers for the authority and audit services -- these need
a genuine socket (unlike the TestClient-based unit tests in
`tests/api/test_authority_service.py` / `test_audit_service.py`), because
`httpx.get`/`httpx.put` here are exactly what the real deployment scripts
use.

The audit-chain half needs a real Postgres, same skip-if-unreachable
convention as the rest of the suite; the PKI/authority-registration half
needs no database at all and always runs.
"""

from __future__ import annotations

import os
import threading
import time

import httpx
import psycopg
import pytest
import uvicorn
from api.audit_service import create_audit_app
from api.authority_service import create_authority_app
from storage.migrate import apply_migrations

from deploy import bootstrap

_URL = os.environ.get("DATABASE_URL")


class _LiveServer:
    """A real uvicorn server bound to 127.0.0.1 on an OS-assigned port."""

    def __init__(self, app) -> None:
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def start(self) -> str:
        self._thread.start()
        deadline = time.monotonic() + 10.0
        while not getattr(self._server, "started", False):
            if time.monotonic() > deadline:
                raise RuntimeError("uvicorn server did not start in time")
            time.sleep(0.05)
        port = self._server.servers[0].sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}"

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10.0)


@pytest.fixture()
def authority_med_url():
    server = _LiveServer(create_authority_app("authority-med", frozenset({"role"})))
    base_url = server.start()
    yield base_url
    server.stop()


def test_register_authority_round_trip(authority_med_url):
    root, _pki = bootstrap.generate_federation_pki(["facility-a", "facility-b"])

    cert_pem = bootstrap.register_authority(authority_med_url, root, "authority-med")
    assert "BEGIN CERTIFICATE" in cert_pem

    stored = httpx.get(f"{authority_med_url}/certificate", timeout=5.0).json()
    assert stored["certificate_pem"] == cert_pem


def test_wait_for_health_times_out_on_unreachable_service():
    with pytest.raises(bootstrap.BootstrapError):
        bootstrap.wait_for_health("http://127.0.0.1:1", timeout=0.5, interval=0.1)


def test_generate_federation_pki_chains_facilities_to_root():
    from crypto_core import certificate_from_pem, verify_certificate_signature

    root, pki = bootstrap.generate_federation_pki(["facility-a", "facility-b"])
    assert set(pki.facilities) == {"facility-a", "facility-b"}

    root_cert = certificate_from_pem(pki.root_certificate_pem.encode("ascii"))
    for facility in pki.facilities.values():
        facility_cert = certificate_from_pem(
            facility.ca_certificate_pem.encode("ascii")
        )
        # Raises if the facility CA certificate was not signed by this root.
        verify_certificate_signature(facility_cert, root.public_key)
        assert facility_cert.issuer == root_cert.subject


@pytest.fixture()
def audit_conn():
    if not _URL:
        pytest.skip("DATABASE_URL not set; bootstrap audit-chain test needs Postgres")
    try:
        conn = psycopg.connect(_URL)
    except psycopg.OperationalError as exc:
        pytest.skip(f"cannot reach Postgres: {exc}")
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)
    conn.commit()
    yield conn
    conn.close()


def test_check_audit_chain_against_live_service(audit_conn):
    server = _LiveServer(create_audit_app(audit_conn, actor_id="audit-service-test"))
    base_url = server.start()
    try:
        head_seq = bootstrap.check_audit_chain(base_url)
        assert head_seq == 0
    finally:
        server.stop()
