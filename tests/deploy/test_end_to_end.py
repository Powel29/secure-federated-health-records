"""Full End-to-End Cross-Hospital Break-Glass Integration Tests (P4-4).

Exercises the entire federated system across live HTTP processes bound to
ephemeral OS sockets via real HTTP requests (httpx):
- Two facilities: facility-a (home) and facility-b (out-of-network)
- Two independent attribute authorities: authority-med and authority-net
- Dedicated standalone audit service with hash-chain custody (C10/C11)
- Root trust anchor with cross-certified facility CAs (C5)

Verifies:
1. Multi-process bootstrap & health checks across all five live services.
2. Authority credential issuance & authoring attribute key exchange.
3. Record ingest at Facility A with 2-of-3 emergency key split & Share 3 deposit.
4. In-network routine clinical read under attribute policy at Facility A.
5. Out-of-network emergency access refusal (403 Policy Denied) at Facility B.
6. Federated patient record discovery across the shared store.
7. Log-before-release share custody: Audit Service commits log entry before
   releasing Share 3.
8. 2-of-3 threshold break-glass unlock at Facility B: assertion validated,
   state -> EMERGENCY_OPEN.
9. PRE decapsulation by emergency clinician & AES-256-GCM medical record decryption.
10. Active emergency search capability while EMERGENCY_OPEN.
11. Time-box session expiry, forced key rotation, and emergency search shutoff.
12. Full SHA-256 audit hash chain verification from genesis through all scenario events.
"""

from __future__ import annotations

import os
import threading
import time

import httpx
import psycopg
import pytest
import uvicorn
from api.audit_client import make_lifecycle_audit_logger
from api.audit_service import create_audit_app
from api.authority_service import create_authority_app
from api.hospital import create_hospital_app
from api.repository import PostgresStorageRepository
from contracts import Facility
from contracts.enums import FacilityStatus
from crypto_core import generate_ec_keypair
from fastapi import FastAPI
from lifecycle.expiry import EmergencyExpiryManager
from storage import repositories as repo_mod
from storage.migrate import apply_migrations

from deploy import bootstrap
from deploy.run_scenario import ScenarioEndpoints, run_scenario

_DATABASE_URL = os.environ.get("DATABASE_URL")


class _LiveServer:
    """A real uvicorn server bound to 127.0.0.1 on an OS-assigned port."""

    def __init__(self, app: FastAPI) -> None:
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
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
def postgres_federation():
    """Spin up all five federation services over live sockets against real Postgres."""
    if not _DATABASE_URL:
        pytest.skip("DATABASE_URL not set; postgres federation test skipped")

    try:
        conn = psycopg.connect(_DATABASE_URL)
    except psycopg.OperationalError as exc:
        pytest.skip(f"cannot reach Postgres: {exc}")

    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)

    repo_mod.insert_authority(conn, "authority-med", "Medical Board", b"\x01")
    repo_mod.insert_authority(conn, "authority-net", "Regional Health Network", b"\x02")
    repo_mod.insert_facility(
        conn,
        Facility(
            facility_id="facility-a",
            display_name="Facility A",
            endpoint="http://127.0.0.1:8001",
            public_key=b"\x03",
            status=FacilityStatus.ACTIVE,
        ),
    )
    repo_mod.insert_facility(
        conn,
        Facility(
            facility_id="facility-b",
            display_name="Facility B",
            endpoint="http://127.0.0.1:8002",
            public_key=b"\x04",
            status=FacilityStatus.ACTIVE,
        ),
    )
    repo_mod.insert_patient(conn, "pat-101", "authority-net")
    conn.commit()

    conn_fa = psycopg.connect(_DATABASE_URL)
    conn_fa.autocommit = True
    repo_fa = PostgresStorageRepository(conn_fa)

    conn_fb = psycopg.connect(_DATABASE_URL)
    conn_fb.autocommit = True
    repo_fb = PostgresStorageRepository(conn_fb)

    timer_priv_a, _ = generate_ec_keypair()
    timer_priv_b, _ = generate_ec_keypair()

    app_audit = create_audit_app(conn, actor_id="audit-service-pg")
    server_audit = _LiveServer(app_audit)
    audit_url = server_audit.start()

    exp_mgr_a = EmergencyExpiryManager(
        signing_key=timer_priv_a,
        timer_actor_id="system:hsm-timer:facility-a",
        default_duration_seconds=5.0,
        audit_logger=make_lifecycle_audit_logger(audit_url),
    )
    exp_mgr_a.start_monitor()

    exp_mgr_b = EmergencyExpiryManager(
        signing_key=timer_priv_b,
        timer_actor_id="system:hsm-timer:facility-b",
        default_duration_seconds=5.0,
        audit_logger=make_lifecycle_audit_logger(audit_url),
    )
    exp_mgr_b.start_monitor()

    app_med = create_authority_app("authority-med", frozenset({"role"}))
    app_net = create_authority_app(
        "authority-net", frozenset({"specialty", "facility", "owner"})
    )
    app_fa = create_hospital_app(
        facility_id="facility-a",
        repository=repo_fa,
        expiry_manager=exp_mgr_a,
        audit_service_url=audit_url,
    )
    app_fb = create_hospital_app(
        facility_id="facility-b",
        repository=repo_fb,
        expiry_manager=exp_mgr_b,
        audit_service_url=audit_url,
    )

    server_med = _LiveServer(app_med)
    server_net = _LiveServer(app_net)
    server_fa = _LiveServer(app_fa)
    server_fb = _LiveServer(app_fb)

    url_med = server_med.start()
    url_net = server_net.start()
    url_fa = server_fa.start()
    url_fb = server_fb.start()

    root_anchor, pki = bootstrap.generate_federation_pki(["facility-a", "facility-b"])
    cert_med = bootstrap.register_authority(url_med, root_anchor, "authority-med")
    cert_net = bootstrap.register_authority(url_net, root_anchor, "authority-net")

    endpoints = ScenarioEndpoints(
        authority_med=url_med,
        authority_net=url_net,
        audit=audit_url,
        facility_a=url_fa,
        facility_b=url_fb,
    )

    config = {
        "root_certificate_pem": pki.root_certificate_pem,
        "facilities": {
            "facility-a": {
                "ca_private_key_pem": pki.facilities["facility-a"].ca_private_key_pem,
                "ca_certificate_pem": pki.facilities["facility-a"].ca_certificate_pem,
            },
            "facility-b": {
                "ca_private_key_pem": pki.facilities["facility-b"].ca_private_key_pem,
                "ca_certificate_pem": pki.facilities["facility-b"].ca_certificate_pem,
            },
        },
        "authorities": {
            "authority-med": {"endpoint": url_med, "certificate_pem": cert_med},
            "authority-net": {"endpoint": url_net, "certificate_pem": cert_net},
        },
        "audit": {"endpoint": audit_url},
    }

    yield {
        "endpoints": endpoints,
        "config": config,
        "conn": conn,
        "exp_mgr_b": exp_mgr_b,
    }

    exp_mgr_a.stop_monitor()
    exp_mgr_b.stop_monitor()
    server_fa.stop()
    server_fb.stop()
    server_audit.stop()
    server_net.stop()
    server_med.stop()
    conn_fa.close()
    conn_fb.close()
    conn.close()


def test_full_scenario_with_postgres(postgres_federation):
    """Run full 9-step scenario on PostgreSQL and verify expiry shutoff."""
    endpoints = postgres_federation["endpoints"]
    config = postgres_federation["config"]
    exp_mgr_b = postgres_federation["exp_mgr_b"]

    # 1. Run all 9 steps of the scenario with a 1.0-second emergency time-box
    success = run_scenario(
        endpoints=endpoints,
        config=config,
        emergency_duration_seconds=1.0,
        verbose=True,
    )
    assert success is True

    # 2. Wait for the 1.0s window to elapse, then trigger the expiry manager sweep
    time.sleep(1.2)
    exp_mgr_b.check_and_expire_due()

    # 3. Verify emergency search is refused and returns 403 Forbidden
    client = httpx.Client(timeout=5.0)
    res = client.post(
        f"{endpoints.facility_b}/records/rec-001/emergency-search",
        json={"search_term": "cardiac"},
    )
    assert res.status_code == 403
    assert "Emergency search unavailable" in res.json()["detail"]
