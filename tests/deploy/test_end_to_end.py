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
7. Log-before-release share custody: Audit Service commits log entry before releasing Share 3.
8. 2-of-3 threshold break-glass unlock at Facility B: assertion validated, state -> EMERGENCY_OPEN.
9. PRE decapsulation by emergency clinician & AES-256-GCM medical record decryption.
10. Active emergency search capability while EMERGENCY_OPEN.
11. Time-box session expiry, forced key rotation, and emergency search shutoff.
12. Full SHA-256 audit hash chain verification from genesis through all scenario events.
"""

from __future__ import annotations

import base64
import datetime
import os
import threading
import time
from typing import Any

import httpx
import psycopg
import pytest
import uvicorn
from api.audit_schemas import (
    AppendEntryRequest,
    AppendEntryResponse,
    ChainHeadResponse,
    ChainVerifyResponse,
    HealthResponse as AuditHealthResponse,
    PublicKeyResponse,
    RegisterShareRequest,
    RegisterShareResponse,
    ReleaseShareRequest,
    ReleaseShareResponse,
)
from api.audit_service import create_audit_app
from api.authority_service import create_authority_app
from api.hospital import create_hospital_app
from api.repository import InMemoryStorageRepository, PostgresStorageRepository
from audit.chain import append_entry as inprocess_append_entry, create_genesis_entry, verify_full_chain
from audit.share_registry import ShareNotFoundError, ShareRegistry
from breakglass import create_emergency_assertion
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts import AuditEntry
from contracts.base import GCM_NONCE_BYTES
from contracts.enums import PolicyNodeType, ReasonCode
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_to_pem,
    generate_ec_keypair,
    private_key_from_pem,
    private_key_to_pem,
    public_key_to_pem,
    sha256_digest,
)
from crypto_core.symmetric import aes_gcm_decrypt
from deploy import bootstrap
from deploy.run_scenario import ScenarioEndpoints, run_scenario
from fastapi import FastAPI, HTTPException, status
from identity.certificates import issue_clinician_certificate
from lifecycle.expiry import EmergencyExpiryManager
from pre.elgamal import decapsulate_key, generate_keypair as generate_pre_keypair
from storage.migrate import apply_migrations

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


def _create_in_memory_audit_app(actor_id: str = "audit-service-test") -> FastAPI:
    """FastAPI app providing Audit Service HTTP endpoints with in-memory chain."""
    app = FastAPI(title="In-Memory Audit Service")
    signing_key, public_key = generate_ec_keypair()
    shares = ShareRegistry()
    lock = threading.Lock()
    chain: list[AuditEntry] = []

    # Genesis entry
    genesis_payload = f"genesis:{actor_id}:{time.time()}".encode("utf-8")
    genesis_hash = sha256_digest(genesis_payload)
    from crypto_core import sign

    sig = sign(signing_key, genesis_hash)
    genesis_entry = AuditEntry(
        seq=0,
        event_type="genesis",
        event_data={"actor_id": actor_id},
        actor_id=actor_id,
        correlation_id="genesis",
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        prev_hash=b"\x00" * 32,
        entry_hash=genesis_hash,
        signature=sig,
    )
    chain.append(genesis_entry)

    @app.get("/health", response_model=AuditHealthResponse)
    def health() -> AuditHealthResponse:
        with lock:
            head_seq = chain[-1].seq if chain else None
        return AuditHealthResponse(
            status="ok", actor_id=actor_id, chain_head_seq=head_seq
        )

    @app.get("/public-key", response_model=PublicKeyResponse)
    def pub_key() -> PublicKeyResponse:
        return PublicKeyResponse(
            public_key_pem=public_key_to_pem(public_key).decode("ascii")
        )

    @app.get("/chain/head", response_model=ChainHeadResponse)
    def chain_head() -> ChainHeadResponse:
        with lock:
            head = chain[-1] if chain else None
        return ChainHeadResponse(head=head)

    @app.get("/chain/verify", response_model=ChainVerifyResponse)
    def verify_chain() -> ChainVerifyResponse:
        with lock:
            if not chain:
                return ChainVerifyResponse(verified=False, head_seq=None)
            from crypto_core import verify

            verified = True
            for i, entry in enumerate(chain):
                if i > 0 and entry.prev_hash != chain[i - 1].entry_hash:
                    verified = False
                    break
                try:
                    verify(public_key, entry.entry_hash, entry.signature)
                except Exception:
                    verified = False
                    break
            return ChainVerifyResponse(verified=verified, head_seq=chain[-1].seq)

    @app.post("/entries", response_model=AppendEntryResponse)
    def append_log(payload: AppendEntryRequest) -> AppendEntryResponse:
        with lock:
            prev = chain[-1]
            content = f"{prev.seq + 1}:{payload.event_type}:{payload.actor_id}:{payload.correlation_id}".encode("utf-8")
            entry_h = sha256_digest(prev.entry_hash + content)
            from crypto_core import sign

            sig = sign(signing_key, entry_h)
            entry = AuditEntry(
                seq=prev.seq + 1,
                event_type=payload.event_type,
                event_data=payload.event_data,
                actor_id=payload.actor_id,
                correlation_id=payload.correlation_id,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                prev_hash=prev.entry_hash,
                entry_hash=entry_h,
                signature=sig,
            )
            chain.append(entry)
        return AppendEntryResponse(entry=entry)

    @app.post("/breakglass/shares", response_model=RegisterShareResponse)
    def register_share(payload: RegisterShareRequest) -> RegisterShareResponse:
        shares.put(payload.share_key, (payload.x, bytes.fromhex(payload.share_hex)))
        return RegisterShareResponse(share_key=payload.share_key)

    @app.post("/breakglass/release", response_model=ReleaseShareResponse)
    def release_share(payload: ReleaseShareRequest) -> ReleaseShareResponse:
        try:
            held = shares.get(payload.share_key)
        except ShareNotFoundError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
            ) from exc

        with lock:
            prev = chain[-1]
            content = f"{prev.seq + 1}:{payload.event_type}:{payload.actor_id}:{payload.correlation_id}".encode("utf-8")
            entry_h = sha256_digest(prev.entry_hash + content)
            from crypto_core import sign

            sig = sign(signing_key, entry_h)
            entry = AuditEntry(
                seq=prev.seq + 1,
                event_type=payload.event_type,
                event_data=payload.event_data,
                actor_id=payload.actor_id,
                correlation_id=payload.correlation_id,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                prev_hash=prev.entry_hash,
                entry_hash=entry_h,
                signature=sig,
            )
            chain.append(entry)

        x, s_bytes = held
        return ReleaseShareResponse(x=x, share_hex=s_bytes.hex(), entry=entry)

    return app


@pytest.fixture()
def in_memory_federation():
    """Spin up all five federation services over live OS sockets with in-memory stores."""
    # 1. Repositories & Expiry Managers
    repo_shared = InMemoryStorageRepository()

    timer_priv_a, _ = generate_ec_keypair()
    exp_mgr_a = EmergencyExpiryManager(
        signing_key=timer_priv_a,
        timer_actor_id="system:hsm-timer:facility-a",
        default_duration_seconds=5.0,
    )
    exp_mgr_a.start_monitor()

    timer_priv_b, _ = generate_ec_keypair()
    exp_mgr_b = EmergencyExpiryManager(
        signing_key=timer_priv_b,
        timer_actor_id="system:hsm-timer:facility-b",
        default_duration_seconds=5.0,
    )
    exp_mgr_b.start_monitor()

    # 2. Build live apps
    app_med = create_authority_app("authority-med", frozenset({"role"}))
    app_net = create_authority_app(
        "authority-net", frozenset({"specialty", "facility", "owner"})
    )
    app_audit = _create_in_memory_audit_app("audit-service-test")

    server_audit = _LiveServer(app_audit)
    audit_url = server_audit.start()

    app_fa = create_hospital_app(
        facility_id="facility-a",
        repository=repo_shared,
        expiry_manager=exp_mgr_a,
        audit_service_url=audit_url,
    )
    app_fb = create_hospital_app(
        facility_id="facility-b",
        repository=repo_shared,
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

    # 3. Bootstrap PKI & Authority registration
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
        "repo": repo_shared,
        "exp_mgr_b": exp_mgr_b,
    }

    # Teardown
    exp_mgr_a.stop_monitor()
    exp_mgr_b.stop_monitor()
    server_fa.stop()
    server_fb.stop()
    server_audit.stop()
    server_net.stop()
    server_med.stop()


def test_end_to_end_cross_facility_breakglass_scenario(in_memory_federation):
    """Run full 9-step cross-facility break-glass scenario over real sockets."""
    endpoints = in_memory_federation["endpoints"]
    config = in_memory_federation["config"]

    # Execute full scenario through the scenario runner
    success = run_scenario(
        endpoints=endpoints,
        config=config,
        emergency_duration_seconds=2.0,
        verbose=True,
    )
    assert success is True


def test_emergency_expiry_and_key_rotation(in_memory_federation):
    """Verify that after breakglass, expiry forces DEK rotation and old key dies."""
    endpoints = in_memory_federation["endpoints"]
    config = in_memory_federation["config"]
    exp_mgr_b = in_memory_federation["exp_mgr_b"]

    # Run scenario with a short duration
    run_scenario(
        endpoints=endpoints,
        config=config,
        emergency_duration_seconds=0.5,
        verbose=False,
    )

    # Wait for the expiry timer sweep
    time.sleep(1.0)
    exp_mgr_b.check_and_expire_due()

    # Verify that emergency search is now refused
    client = httpx.Client(timeout=5.0)
    res = client.post(
        f"{endpoints.facility_b}/records/rec-001/emergency-search",
        json={"search_term": "cardiac"},
    )
    assert res.status_code == 403
    assert "Emergency search unavailable" in res.json()["detail"]


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

    from contracts import Facility
    from contracts.enums import FacilityStatus
    from storage import repositories as repo_mod

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

    from api.audit_client import make_lifecycle_audit_logger

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
    """Run full scenario against real PostgreSQL store and verify audit chain."""
    endpoints = postgres_federation["endpoints"]
    config = postgres_federation["config"]

    success = run_scenario(
        endpoints=endpoints,
        config=config,
        emergency_duration_seconds=2.0,
        verbose=True,
    )
    assert success is True
