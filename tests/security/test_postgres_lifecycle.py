"""Lifecycle and restart claims on the real store (review N1, N13, F37, F43).

The in-memory repository shares one Python object between "processes", so a
restart there proves nothing about the store. Every test here gives each
simulated facility process its own Postgres connection and its own app.
"""

from __future__ import annotations

import os
import threading

import psycopg
import pytest
from api.audit_service import create_audit_app
from api.hospital import create_hospital_app
from api.repository import PostgresStorageRepository
from contracts import Facility
from contracts.enums import FacilityStatus, LifecycleState
from crypto_core import generate_ec_keypair, public_key_to_pem
from fastapi.testclient import TestClient
from lifecycle.expiry import EmergencyExpiryManager
from storage.migrate import apply_migrations
from storage.repositories import insert_authority, insert_facility, insert_patient

from tests.api.conftest import (  # noqa: F401
    RecordingAuditSink,
    RecordingRotationPorts,
    attribute_materials,
    federation_pki,
    make_trust,
)
from tests.sealing import seal_all
from tests.security.conftest import skip_or_fail_without_postgres
from tests.security.test_p51_system_claims import (
    _SURGEON_ONLY,
    PATIENT,
    RECORD,
    _clinician_keyring,
    _owner_keyring,
    _read,
    _revoke_payload,
    _seed,
    _unlock_payload,
)

_DB_URL = os.environ.get("DATABASE_URL")


def _connect() -> psycopg.Connection:
    conn = psycopg.connect(_DB_URL)
    conn.autocommit = True
    return conn


@pytest.fixture()
def store(federation_pki, attribute_materials):  # noqa: F811
    """A fresh schema with the registry rows records need, plus one record."""
    if not _DB_URL:
        skip_or_fail_without_postgres("DATABASE_URL not set; this test needs Postgres")
    try:
        admin = _connect()
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    with admin.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    apply_migrations(admin)
    _, pub = generate_ec_keypair()
    for authority in ("authority-med", "authority-net"):
        insert_authority(admin, authority, authority, public_key_to_pem(pub))
    insert_facility(
        admin,
        Facility(
            facility_id="facility-a",
            display_name="A",
            endpoint="http://facility-a",
            public_key=public_key_to_pem(pub),
            status=FacilityStatus.ACTIVE,
        ),
    )
    insert_patient(admin, PATIENT, "authority-net")
    seeded = _seed(
        PostgresStorageRepository(admin), attribute_materials, federation_pki
    )
    opened: list[psycopg.Connection] = [admin]
    rotation = RecordingRotationPorts(attribute_materials["attr_keyring"])

    def facility_process(duration: float = 60.0) -> TestClient:
        """One facility process: its own connection, replay store and timer."""
        conn = _connect()
        opened.append(conn)
        manager = EmergencyExpiryManager(
            signing_key=federation_pki["life_priv"], default_duration_seconds=duration
        )
        app = create_hospital_app(
            facility_id="facility-a",
            repository=PostgresStorageRepository(conn),
            expiry_manager=manager,
            trust=make_trust(federation_pki),
            audit_sink=RecordingAuditSink(),
            rotation_ports=rotation.ports,
        )
        return federation_pki["services"].client(app, "facility-a")

    yield {
        "admin": admin,
        "repo": PostgresStorageRepository(admin),
        "process": facility_process,
        "rotation": rotation,
        "pki": federation_pki,
        "attrs": attribute_materials,
        **seeded,
    }
    for conn in opened:
        conn.close()


def _hospital(store) -> dict:
    """The dict shape _unlock_payload expects."""
    return {"pki": store["pki"], "shares": store["shares"], "repo": store["repo"]}


def test_concurrent_breakglass_one_wins(store):
    """N1: two facility processes open one record at once -- one 200, one 409."""
    a, b = store["process"](), store["process"]()
    results: list[int] = []
    barrier = threading.Barrier(2)

    def open_record(client):
        payload = _unlock_payload(_hospital(store), target=client)
        barrier.wait()
        results.append(
            client.post(f"/records/{RECORD}/breakglass", json=payload).status_code
        )

    threads = [threading.Thread(target=open_record, args=(c,)) for c in (a, b)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(results) == [200, 409]
    assert store["repo"].get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN


def test_timer_mirror_does_not_overwrite_a_changed_state(store):
    """N1: a record revoked mid-session is still REVOKED after expiry."""
    client = store["process"]()
    assert (
        client.post(
            f"/records/{RECORD}/breakglass",
            json=_unlock_payload(_hospital(store), target=client),
        ).status_code
        == 200
    )
    store["repo"].upsert_lifecycle_state(RECORD, LifecycleState.REVOKED)

    client.app.state.expiry_manager.expire_session(RECORD, force=True)

    assert store["repo"].get_lifecycle_state(RECORD) is LifecycleState.REVOKED


def test_expiry_returns_the_stored_state_to_granted(store):
    """N1: with nothing in the way, the timer's transitions reach the store."""
    client = store["process"]()
    client.post(
        f"/records/{RECORD}/breakglass",
        json=_unlock_payload(_hospital(store), target=client),
    )
    client.app.state.expiry_manager.expire_session(RECORD, force=True)
    assert store["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED


def test_stale_emergency_open_returns_409_not_silent_reset(store):
    """N1: another process's session is not reset because this one holds none."""
    first = store["process"]()
    assert (
        first.post(
            f"/records/{RECORD}/breakglass",
            json=_unlock_payload(_hospital(store), target=first),
        ).status_code
        == 200
    )
    second = store["process"]()
    response = second.post(
        f"/records/{RECORD}/breakglass",
        json=_unlock_payload(_hospital(store), target=second),
    )
    assert response.status_code == 409
    assert store["repo"].get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN


@pytest.mark.claim("C1", level="system")
def test_c1_revoked_clinician_cannot_read_on_postgres(store):
    """C1 on the real store: revocation re-encrypts the stored row.

    The in-memory C1 test proves the policy and rotation logic; this one proves
    the same outcome when the ciphertext, DEK wrappings and policy live in
    Postgres, so a revoked clinician is locked out of what the store holds.
    """
    client = store["process"]()
    attrs = store["attrs"]

    before = _read(client, "dr-alice", _clinician_keyring(attrs))
    assert before.status_code == 200, before.text

    revoked = client.post(
        f"/records/{RECORD}/revoke", json=_revoke_payload(store, _SURGEON_ONLY)
    )
    assert revoked.status_code == 200, revoked.text
    assert store["repo"].get_lifecycle_state(RECORD) is LifecycleState.REVOKED

    # A restarted process reads the same store: the lock-out is the data.
    after = _read(store["process"](), "dr-alice", _clinician_keyring(attrs))
    assert after.status_code == 403
    assert "plaintext_b64" not in after.text

    assert _read(client, PATIENT, _owner_keyring(attrs)).status_code == 200


@pytest.mark.claim("C8", level="system")
def test_c8_replayed_assertion_rejected_across_processes_on_postgres(store):
    """N13 / C8: a replay into a second facility process on the same store fails."""
    first = store["process"]()
    payload = _unlock_payload(_hospital(store), target=first)
    assert first.post(f"/records/{RECORD}/breakglass", json=payload).status_code == 200
    first.app.state.expiry_manager.expire_session(RECORD, force=True)

    restarted = store["process"]()
    # A new process has a new share key; reseal so the replay check is what
    # refuses (ADR-0079).
    resealed = {
        **payload,
        "sealed_shares": seal_all(restarted, RECORD, list(store["shares"][:2])),
    }
    replay = restarted.post(f"/records/{RECORD}/breakglass", json=resealed)
    assert replay.status_code == 400
    assert "ReplayedAssertionError" in replay.json()["detail"]
    assert "rewrapped_dek_b64" not in replay.text


def test_read_succeeds_after_facility_restart(store):
    """F43: a new facility process reads a record another process stored."""
    first = store["process"]()
    owner = _owner_keyring(store["attrs"])
    assert _read(first, PATIENT, owner).status_code == 200

    restarted = store["process"]()
    response = _read(restarted, PATIENT, owner)
    assert response.status_code == 200, response.text


def test_tampered_genesis_stops_the_audit_service(store):
    """F37: if the chain does not verify at boot, the audit service never starts.

    Every federation service that writes to the chain waits for the audit
    service to be healthy, so nothing else starts either.
    """
    admin = store["admin"]
    identity = store["pki"]["services"].identity("audit-service")
    create_audit_app(
        admin,
        actor_id="audit-boot",
        service_root=store["pki"]["root"].certificate,
        identity=identity,
    )  # writes the genesis entry
    with admin.cursor() as cur:
        cur.execute("UPDATE audit_log SET actor_id = 'forged' WHERE seq = 0")

    with pytest.raises(Exception) as excinfo:  # noqa: B017 -- any verify error
        create_audit_app(
            admin,
            actor_id="audit-boot",
            service_root=store["pki"]["root"].certificate,
            identity=identity,
        )
    assert type(excinfo.value).__name__ in {
        "InvalidSignatureError",
        "TamperedEntryError",
        "ChainBreakError",
    }
