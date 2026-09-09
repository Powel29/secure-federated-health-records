"""Tests for the standalone Audit Service (P4-2, C10/C11/C14).

Needs a real Postgres -- same skip-if-unreachable convention as
``tests/storage/conftest.py`` and ``tests/audit/conftest.py``. Uses its own
dedicated connection rather than a shared session fixture, because
``create_audit_app`` switches its connection to autocommit mode (so every
request durably commits immediately, matching a real deployed process) --
that must not leak into another test module's rollback-based isolation.
"""

from __future__ import annotations

import os

import psycopg
import pytest
from api.audit_service import create_audit_app
from fastapi.testclient import TestClient
from storage.migrate import apply_migrations

_URL = os.environ.get("DATABASE_URL")


@pytest.fixture()
def audit_conn():
    if not _URL:
        pytest.skip("DATABASE_URL not set; audit service tests need Postgres")
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


@pytest.fixture()
def client(audit_conn) -> TestClient:
    app = create_audit_app(audit_conn, actor_id="audit-service-test")
    return TestClient(app)


def test_health_reports_genesis_head(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["actor_id"] == "audit-service-test"
    assert body["chain_head_seq"] == 0


def test_public_key_is_pem(client: TestClient) -> None:
    r = client.get("/public-key")
    assert r.status_code == 200
    assert "BEGIN PUBLIC KEY" in r.json()["public_key_pem"]


def test_chain_verifies_after_genesis(client: TestClient) -> None:
    r = client.get("/chain/verify")
    assert r.status_code == 200
    assert r.json() == {"verified": True, "head_seq": 0}


def test_second_boot_against_same_chain_does_not_duplicate_genesis(
    audit_conn,
) -> None:
    """Restarting the service (with its key reloaded) must not re-run genesis."""
    from crypto_core import generate_ec_keypair

    signing_key, _ = generate_ec_keypair()
    create_audit_app(audit_conn, signing_key, actor_id="audit-service-test")
    app2 = create_audit_app(audit_conn, signing_key, actor_id="audit-service-test")
    client2 = TestClient(app2)
    assert client2.get("/health").json()["chain_head_seq"] == 0


def test_append_entry_extends_chain(client: TestClient) -> None:
    r = client.post(
        "/entries",
        json={
            "event_type": "federation_discovery",
            "event_data": {"patient_hash": "abc"},
            "actor_id": "facility-a",
            "correlation_id": "corr-1",
        },
    )
    assert r.status_code == 200
    entry = r.json()["entry"]
    assert entry["seq"] == 1
    assert entry["event_type"] == "federation_discovery"
    assert entry["actor_id"] == "facility-a"

    head = client.get("/chain/head").json()["head"]
    assert head["seq"] == 1
    assert head["entry_hash"] == entry["entry_hash"]

    verify = client.get("/chain/verify").json()
    assert verify == {"verified": True, "head_seq": 1}


def test_share_release_only_after_commit(client: TestClient) -> None:
    """The released share and the chain head come from the same committed entry."""
    reg = client.post(
        "/breakglass/shares",
        json={"share_key": "rec-1", "x": 3, "share_hex": "deadbeef"},
    )
    assert reg.status_code == 201

    r = client.post(
        "/breakglass/release",
        json={
            "share_key": "rec-1",
            "event_data": {"record_id": "rec-1"},
            "actor_id": "audit-service-test",
            "correlation_id": "corr-2",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["x"] == 3
    assert body["share_hex"] == "deadbeef"
    assert body["entry"]["event_type"] == "breakglass_share_release"
    assert body["entry"]["seq"] == 1
    # Never log the share itself alongside the entry (CONVENTIONS.md §2 rule 3).
    assert "deadbeef" not in str(body["entry"]["event_data"])

    head = client.get("/chain/head").json()["head"]
    assert head["entry_hash"] == body["entry"]["entry_hash"]


def test_release_share_without_registration_is_not_found(client: TestClient) -> None:
    r = client.post(
        "/breakglass/release",
        json={
            "share_key": "unknown-record",
            "event_data": {},
            "actor_id": "audit-service-test",
            "correlation_id": "corr-3",
        },
    )
    assert r.status_code == 404


def test_release_share_fails_closed_on_commit_failure(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No log commit, no share -- P3-4's headline property, enforced over HTTP."""
    reg = client.post(
        "/breakglass/shares",
        json={"share_key": "rec-2", "x": 1, "share_hex": "cafef00d"},
    )
    assert reg.status_code == 201

    import audit.share_custody as share_custody_module

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated write failure")

    monkeypatch.setattr(share_custody_module, "append_entry", _boom)

    r = client.post(
        "/breakglass/release",
        json={
            "share_key": "rec-2",
            "event_data": {},
            "actor_id": "audit-service-test",
            "correlation_id": "corr-4",
        },
    )
    assert r.status_code == 503

    # The share was never handed out -- still held, not consumed.
    assert client.app.state.shares.has("rec-2")
    head = client.get("/chain/head").json()["head"]
    assert (
        head["seq"] == 0
    )  # unchanged: genesis only, the failed append never committed
