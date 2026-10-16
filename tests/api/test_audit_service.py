"""Tests for the standalone Audit Service (P4-2, C10/C11/C14).

Needs a real Postgres -- same skip-if-unreachable convention as
``tests/storage/conftest.py`` and ``tests/audit/conftest.py``. Uses its own
dedicated connection rather than a shared session fixture, because
``create_audit_app`` switches its connection to autocommit mode (so every
request durably commits immediately, matching a real deployed process) --
that must not leak into another test module's rollback-based isolation.

Every write is signed as a federation service (ADR-0066); share 3 is released
only against an emergency assertion this service validates itself
(ADR-0067); a share is replaced only by a facility during its record's expiry
rotation (ADR-0069).
"""

from __future__ import annotations

import os

import psycopg
import pytest
from api.audit_service import create_audit_app
from breakglass import create_emergency_assertion
from breakglass.assertion import clinical_context_digest
from breakglass.share_sealing import (
    SealedShare,
    ShareKeyStatement,
    ShareSealingKey,
    make_key_statement,
    open_sealed_share,
)
from contracts import Facility
from contracts.enums import FacilityStatus, LifecycleState, ReasonCode
from crypto_core import certificate_to_pem, generate_ec_keypair
from fastapi.testclient import TestClient
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import generate_root_anchor
from records.service import encrypt_record
from storage.migrate import apply_migrations
from storage.repositories import (
    get_chain_head,
    insert_authority,
    insert_facility,
    insert_patient,
    insert_record,
    upsert_lifecycle_state,
)

from tests.api.conftest import make_trust
from tests.sealing import seal_for
from tests.security.conftest import skip_or_fail_without_postgres

_URL = os.environ.get("DATABASE_URL")
JUSTIFICATION = "Unresponsive on arrival; medication history needed now."


@pytest.fixture()
def audit_conn():
    if not _URL:
        skip_or_fail_without_postgres(
            "DATABASE_URL not set; audit service tests need Postgres"
        )
    try:
        conn = psycopg.connect(_URL)
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture()
def audit_app(audit_conn, federation_pki):
    return create_audit_app(
        audit_conn,
        actor_id="audit-service-test",
        service_root=federation_pki["root"].certificate,
        trust=make_trust(federation_pki),
        identity=federation_pki["services"].identity("audit-service"),
    )


@pytest.fixture()
def client(audit_app, federation_pki) -> TestClient:
    """Signed as the custodian, which deposits and requests share 3."""
    return federation_pki["services"].client(
        audit_app, "audit-service", caller="custodian"
    )


def _release(pki, share_key: str, correlation_id: str, **overrides) -> dict:
    """A release request carrying Dr Alice's assertion, bound to ``share_key``."""
    assertion = create_emergency_assertion(
        patient_id="patient-001",
        clinician_id="dr-alice",
        facility_id="facility-a",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=overrides.pop("signing_key", pki["alice_priv"]),
        clinical_context_digest=clinical_context_digest(share_key, JUSTIFICATION, ""),
    )
    body = {
        "share_key": share_key,
        "event_data": {"record_id": share_key},
        "actor_id": "audit-service-test",
        "correlation_id": correlation_id,
        "assertion": assertion.model_dump(mode="json"),
        "clinician_certificate_pem": certificate_to_pem(pki["alice_cert"]).decode(
            "ascii"
        ),
        "justification": JUSTIFICATION,
        # Share 3 is sealed to facility-a's gate (ADR-0079).
        "recipient": _gate(pki)[1].model_dump(mode="json"),
    }
    body.update(overrides)
    return body


def _gate(pki) -> tuple[ShareSealingKey, ShareKeyStatement]:
    """facility-a's share key and the statement it would publish."""
    if "gate" not in pki:
        identity = pki["services"].identity("facility-a")
        key = ShareSealingKey.generate()
        pki["gate"] = (
            key,
            make_key_statement(
                key,
                service_id=identity.service_id,
                kind=identity.kind,
                signing_key=identity.signing_key,
                certificate_pem=identity.certificate_pem,
            ),
        )
    return pki["gate"]


def _released_hex(pki, share_key: str, response) -> str:
    """The share in a release response, opened as facility-a's gate would."""
    _x, value = open_sealed_share(
        SealedShare.model_validate(response.json()["sealed_share"]),
        record_id=share_key,
        service_id="facility-a",
        key=_gate(pki)[0],
    )
    return value.hex()


def _sealed(client, share_key: str, share_hex: str, x: int = 3) -> dict:
    return seal_for(client, share_key, (x, bytes.fromhex(share_hex)))


def _register(client, share_key: str, share_hex: str = "deadbeef", x: int = 3):
    return client.post(
        "/breakglass/shares",
        json={
            "share_key": share_key,
            "sealed_share": _sealed(client, share_key, share_hex, x),
        },
    )


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
    audit_conn, federation_pki
) -> None:
    """Restarting the service (with its key reloaded) must not re-run genesis."""
    signing_key, _ = generate_ec_keypair()
    root = federation_pki["root"].certificate
    identity = federation_pki["services"].identity("audit-service")
    create_audit_app(
        audit_conn,
        signing_key,
        actor_id="audit-service-test",
        service_root=root,
        identity=identity,
    )
    app2 = create_audit_app(
        audit_conn,
        signing_key,
        actor_id="audit-service-test",
        service_root=root,
        identity=identity,
    )
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


def test_share_registration_never_overwrites(client: TestClient, federation_pki):
    """Review F4: a second share under the same key is refused (409) and the
    original share is still the one released."""
    assert _register(client, "rec-dup").status_code == 201
    assert _register(client, "rec-dup", "00000000").status_code == 409
    released = client.post(
        "/breakglass/release", json=_release(federation_pki, "rec-dup", "corr-dup")
    )
    assert _released_hex(federation_pki, "rec-dup", released) == "deadbeef"


def test_share_release_only_after_commit(client: TestClient, federation_pki) -> None:
    """The released share and the chain head come from the same committed entry."""
    assert _register(client, "rec-1").status_code == 201

    r = client.post(
        "/breakglass/release", json=_release(federation_pki, "rec-1", "corr-2")
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sealed_share"]["x"] == 3
    assert _released_hex(federation_pki, "rec-1", r) == "deadbeef"
    # Sealed to the gate: the share's bytes are not in the response (ADR-0079).
    assert "deadbeef" not in r.text
    assert body["entry"]["event_type"] == "breakglass_share_release"
    assert body["entry"]["seq"] == 1
    # Never log the share itself alongside the entry (CONVENTIONS.md §2 rule 3).
    assert "deadbeef" not in str(body["entry"]["event_data"])
    # The entry records what was validated, not what the caller wrote, and
    # never the justification text itself.
    data = body["entry"]["event_data"]
    assert data["clinician_id"] == "dr-alice"
    assert data["patient_id"] == "patient-001"
    assert JUSTIFICATION not in str(body["entry"])

    head = client.get("/chain/head").json()["head"]
    assert head["entry_hash"] == body["entry"]["entry_hash"]


def test_release_share_without_registration_is_not_found(
    client: TestClient, federation_pki
) -> None:
    r = client.post(
        "/breakglass/release",
        json=_release(federation_pki, "unknown-record", "corr-3"),
    )
    assert r.status_code == 404


@pytest.mark.claim("C2", level="system")
def test_release_share_fails_closed_on_commit_failure(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, federation_pki
) -> None:
    """No log commit, no share -- P3-4's headline property, enforced over HTTP."""
    assert _register(client, "rec-2", "cafef00d", x=1).status_code == 201

    import audit.share_custody as share_custody_module

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated write failure")

    monkeypatch.setattr(share_custody_module, "append_entry", _boom)

    r = client.post(
        "/breakglass/release", json=_release(federation_pki, "rec-2", "corr-4")
    )
    assert r.status_code == 503

    # The share was never handed out -- still held, not consumed.
    assert client.app.state.shares.has("rec-2")
    head = client.get("/chain/head").json()["head"]
    assert (
        head["seq"] == 0
    )  # unchanged: genesis only, the failed append never committed


# ---------------------------------------------------------------------------
# ADR-0067 (review D1-a): the audit service validates the assertion itself
# ---------------------------------------------------------------------------


def _nothing_released(client, response) -> None:
    assert "sealed_share" not in response.text
    assert client.get("/chain/head").json()["head"]["seq"] == 0


class TestReleaseNeedsAValidAssertion:
    """Share 3 moves only against an assertion validated here. Each refusal is
    checked against the positive control in the same fixture."""

    def test_positive_control_valid_assertion_releases(self, client, federation_pki):
        _register(client, "rec-ok")
        ok = client.post(
            "/breakglass/release", json=_release(federation_pki, "rec-ok", "corr-ok")
        )
        assert ok.status_code == 200, ok.text

    def test_no_assertion_is_refused(self, client, federation_pki):
        _register(client, "rec-a")
        body = _release(federation_pki, "rec-a", "corr-a")
        del body["assertion"], body["clinician_certificate_pem"]
        r = client.post("/breakglass/release", json=body)
        assert r.status_code == 422
        _nothing_released(client, r)

    @pytest.mark.claim("C3", level="system")
    def test_assertion_for_another_record_is_refused(self, client, federation_pki):
        _register(client, "rec-b")
        body = _release(federation_pki, "rec-elsewhere", "corr-b")
        body["share_key"] = "rec-b"
        r = client.post("/breakglass/release", json=body)
        assert r.status_code == 403
        _nothing_released(client, r)

    @pytest.mark.claim("C3", level="system")
    def test_assertion_not_signed_by_the_certificate_key_is_refused(
        self, client, federation_pki
    ):
        _register(client, "rec-c")
        forger, _ = generate_ec_keypair()
        r = client.post(
            "/breakglass/release",
            json=_release(federation_pki, "rec-c", "corr-c", signing_key=forger),
        )
        assert r.status_code == 400
        assert "InvalidSignatureError" in r.json()["detail"]
        _nothing_released(client, r)

    @pytest.mark.claim("C3", level="system")
    def test_clinician_from_an_untrusted_ca_is_refused(self, client, federation_pki):
        _register(client, "rec-d")
        rogue_root = generate_root_anchor()
        rogue_ca_priv, rogue_ca_pub = generate_ec_keypair()
        rogue_ca = issue_facility_ca_certificate(rogue_root, "facility-a", rogue_ca_pub)
        rogue_cert = issue_clinician_certificate(
            rogue_ca_priv, rogue_ca, "dr-alice", federation_pki["alice_pub"]
        )
        body = _release(federation_pki, "rec-d", "corr-d")
        body["clinician_certificate_pem"] = certificate_to_pem(rogue_cert).decode()
        r = client.post("/breakglass/release", json=body)
        assert r.status_code == 403
        _nothing_released(client, r)

    def test_share_3_goes_only_to_a_facility_gate(self, client, federation_pki):
        """ADR-0079: share 3 is sealed only to a root-certified facility's key;
        a custodian statement (a caller that also holds share 1) is refused
        before anything is committed."""
        _register(client, "rec-h")
        identity = federation_pki["services"].identity("custodian")
        custodian = make_key_statement(
            ShareSealingKey.generate(),
            service_id=identity.service_id,
            kind=identity.kind,
            signing_key=identity.signing_key,
            certificate_pem=identity.certificate_pem,
        )
        body = _release(federation_pki, "rec-h", "corr-h")
        body["recipient"] = custodian.model_dump(mode="json")
        r = client.post("/breakglass/release", json=body)
        assert r.status_code == 403
        assert "not a facility" in r.json()["detail"]
        _nothing_released(client, r)

    @pytest.mark.claim("C3", level="system")
    def test_a_replayed_assertion_is_refused(self, client, federation_pki):
        _register(client, "rec-e")
        body = _release(federation_pki, "rec-e", "corr-e")
        assert client.post("/breakglass/release", json=body).status_code == 200
        again = client.post("/breakglass/release", json=body)
        assert again.status_code == 400
        assert "ReplayedAssertionError" in again.json()["detail"]
        assert "sealed_share" not in again.text

    @pytest.mark.claim("C9", level="system")
    def test_a_portal_may_not_request_share_3(self, audit_app, federation_pki):
        portal = federation_pki["services"].client(
            audit_app, "audit-service", caller="portal"
        )
        r = portal.post(
            "/breakglass/release", json=_release(federation_pki, "rec-f", "corr-f")
        )
        assert r.status_code == 403
        assert "sealed_share" not in r.text

    @pytest.mark.claim("C9", level="system")
    def test_an_unsigned_request_is_refused(self, audit_app, federation_pki):
        r = TestClient(audit_app).post(
            "/breakglass/release", json=_release(federation_pki, "rec-g", "corr-g")
        )
        assert r.status_code == 401
        assert "sealed_share" not in r.text


# ---------------------------------------------------------------------------
# ADR-0069: share replacement at the record's expiry rotation
# ---------------------------------------------------------------------------


def _seed_record(conn, record_id: str, state: LifecycleState) -> None:
    """A store row for ``record_id`` in ``state`` (the audit service reads it)."""
    if conn.execute("SELECT 1 FROM facilities").fetchone() is None:
        insert_authority(conn, "authority-net", "Net", b"\x01")
        insert_facility(
            conn,
            Facility(
                facility_id="facility-a",
                display_name="A",
                endpoint="http://a",
                public_key=b"\x02",
                status=FacilityStatus.ACTIVE,
            ),
        )
        insert_patient(conn, "patient-001", "authority-net")
    record, _dek = encrypt_record(
        plaintext=b"{}",
        patient_id="patient-001",
        facility_id="facility-a",
        policy_id="pol-x",
        record_id=record_id,
    )
    insert_record(conn, record)
    upsert_lifecycle_state(conn, record_id, state)
    conn.commit()


class TestShareReplacement:
    """Only a facility, only during an expiry or revocation rotation, only a
    later generation (ADR-0069, ADR-0080, ADR-0081)."""

    def _facility(self, audit_app, federation_pki):
        return federation_pki["services"].client(
            audit_app, "audit-service", caller="facility-a"
        )

    def test_positive_control_facility_replaces_during_expiry(
        self, client, audit_app, audit_conn, federation_pki
    ):
        _register(client, "rec-r1")
        _seed_record(audit_conn, "rec-r1", LifecycleState.EXPIRED)
        facility = self._facility(audit_app, federation_pki)
        body = {"sealed_share": _sealed(client, "rec-r1", "abcdef01"), "generation": 1}
        assert facility.put("/breakglass/shares/rec-r1", json=body).status_code == 200
        # A retry of the same replacement is a no-op, not an error.
        assert facility.put("/breakglass/shares/rec-r1", json=body).status_code == 200
        released = client.post(
            "/breakglass/release", json=_release(federation_pki, "rec-r1", "corr-r1")
        )
        assert _released_hex(federation_pki, "rec-r1", released) == "abcdef01"

    def test_replacement_outside_expiry_is_refused(
        self, client, audit_app, audit_conn, federation_pki
    ):
        _register(client, "rec-r2")
        _seed_record(audit_conn, "rec-r2", LifecycleState.GRANTED)
        r = self._facility(audit_app, federation_pki).put(
            "/breakglass/shares/rec-r2",
            json={
                "sealed_share": _sealed(client, "rec-r2", "abcdef01"),
                "generation": 1,
            },
        )
        assert r.status_code == 409
        assert client.app.state.shares.get("rec-r2") == (3, bytes.fromhex("deadbeef"))

    def test_only_a_later_generation_replaces(
        self, client, audit_app, audit_conn, federation_pki
    ):
        """A recovered rotation may skip a generation (ADR-0081); a share is
        never rolled back or swapped within its generation."""
        _register(client, "rec-r3")
        _seed_record(audit_conn, "rec-r3", LifecycleState.EXPIRED)
        facility = self._facility(audit_app, federation_pki)
        skipped = facility.put(
            "/breakglass/shares/rec-r3",
            json={
                "sealed_share": _sealed(client, "rec-r3", "abcdef01"),
                "generation": 2,
            },
        )
        assert skipped.status_code == 200
        assert client.app.state.shares.generation("rec-r3") == 2
        other = _sealed(client, "rec-r3", "abcdef02")
        for generation in (1, 2):  # a rollback, then a swap within generation 2
            r = facility.put(
                "/breakglass/shares/rec-r3",
                json={"sealed_share": other, "generation": generation},
            )
            assert r.status_code == 409
        assert client.app.state.shares.get("rec-r3") == (3, bytes.fromhex("abcdef01"))

    def test_a_revocation_rotation_replaces_the_share(
        self, client, audit_app, audit_conn, federation_pki
    ):
        """A patient's revocation re-keys the emergency path too (ADR-0080)."""
        _register(client, "rec-r5")
        _seed_record(audit_conn, "rec-r5", LifecycleState.REVOKED)
        r = self._facility(audit_app, federation_pki).put(
            "/breakglass/shares/rec-r5",
            json={
                "sealed_share": _sealed(client, "rec-r5", "abcdef01"),
                "generation": 1,
            },
        )
        assert r.status_code == 200
        assert client.app.state.shares.generation("rec-r5") == 1

    def test_only_a_facility_may_replace(self, client, audit_conn, federation_pki):
        _register(client, "rec-r4")
        _seed_record(audit_conn, "rec-r4", LifecycleState.EXPIRED)
        r = client.put(  # signed as the custodian
            "/breakglass/shares/rec-r4",
            json={
                "sealed_share": _sealed(client, "rec-r4", "abcdef01"),
                "generation": 1,
            },
        )
        assert r.status_code == 403
        assert client.app.state.shares.generation("rec-r4") == 0
        assert get_chain_head(audit_conn).seq == 0
