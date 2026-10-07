"""P5-1 system-level negative tests: each paper claim through the running services.

The module-level suite proves each control inside its module. These tests
drive the real FastAPI apps -- hospital node, audit service, attribute
authority -- because the paper's claims are about the system, and the
2026-10-07 review shows several controls that hold in their module but not
through the API around them.

A test that fails today keeps its full-strength assertion and is marked
``xfail(strict=True)`` with the review finding that blocks it (ADR-0046). The
run turns red the day the fix lands, so the marker must come off and the
claim flips to "holds" in ``python -m tests.security.claims --table``.

Every negative test first shows the legitimate path succeeding in the same
fixture, so a refusal means the control worked, not that the setup broke.
"""

from __future__ import annotations

import base64
import os
import secrets

import psycopg
import pytest
from api.audit_service import create_audit_app
from api.authority_service import create_authority_app
from api.hospital import create_hospital_app
from api.repository import InMemoryStorageRepository
from breakglass import create_emergency_assertion
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts import TransitionEvent
from contracts.enums import LifecycleState, PolicyNodeType, ReasonCode
from contracts.policy import Attribute, PolicyTree
from crypto_core import certificate_to_pem, private_key_to_pem
from fastapi.testclient import TestClient
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import verify_transition_event
from policy.engine import unwrap_dek_via_policy
from records.ingest import ingest_record
from storage.migrate import apply_migrations

# PKI and attribute fixtures are shared with the API suite; the hospital
# fixture below is our own (it seeds the ingest-produced emergency wrapping).
from tests.api.conftest import attribute_materials, federation_pki  # noqa: F401
from tests.security.conftest import skip_or_fail_without_postgres

RECORD = "rec-001"
PATIENT = "patient-001"
PLAINTEXT = b'{"diagnosis": "Coronary artery disease", "severity": "acute"}'
_DB_URL = os.environ.get("DATABASE_URL")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _seed(repo: InMemoryStorageRepository, attrs: dict) -> dict:
    em_key = generate_emergency_key()
    ingested = ingest_record(
        plaintext=PLAINTEXT,
        patient_id=PATIENT,
        facility_id="facility-a",
        owner_authority_id="authority-net",
        clinical_policy=attrs["clinical_policy"],
        attribute_keyring=attrs["attr_keyring"],
        search_terms=["cardiac", "acute"],
        emergency_key=em_key,
        content_type="application/json",
        record_id=RECORD,
    )
    repo.insert_record(ingested.record)
    repo.insert_dek_wrapping(ingested.dek_wrapping)
    repo.insert_dek_wrapping(ingested.emergency_dek_wrapping)
    repo.store_compiled_policy(ingested.record.policy_id, ingested.compiled_policy)
    repo.upsert_lifecycle_state(record_id=RECORD, state=LifecycleState.GRANTED)
    for token in ingested.search_tokens.values():
        repo.insert_search_term(RECORD, token)
    return {
        "ingested": ingested,
        "em_key": em_key,
        "shares": split_emergency_key(em_key),
    }


def _hospital_app(repo: InMemoryStorageRepository, life_priv) -> TestClient:
    manager = EmergencyExpiryManager(
        signing_key=life_priv, default_duration_seconds=60.0
    )
    app = create_hospital_app(
        facility_id="facility-a", repository=repo, expiry_manager=manager
    )
    return TestClient(app)


@pytest.fixture()
def hospital(federation_pki, attribute_materials):  # noqa: F811
    repo = InMemoryStorageRepository()
    seeded = _seed(repo, attribute_materials)
    return {
        "repo": repo,
        "client": _hospital_app(repo, federation_pki["life_priv"]),
        "pki": federation_pki,
        "attrs": attribute_materials,
        **seeded,
    }


@pytest.fixture()
def audit_client():
    """A real audit service on Postgres (same pattern as tests/api)."""
    if not _DB_URL:
        skip_or_fail_without_postgres(
            "DATABASE_URL not set; audit service needs Postgres"
        )
    try:
        conn = psycopg.connect(_DB_URL)
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)
    conn.commit()
    yield TestClient(create_audit_app(conn, actor_id="audit-p51")), conn
    conn.close()


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------


def _clinician_keyring(attrs: dict) -> dict[str, str]:
    """Physician + cardiology: satisfies the clinical branch, no owner key."""
    return {k: v for k, v in attrs["b64_keyring"].items() if not k.endswith(PATIENT)}


def _owner_keyring(attrs: dict) -> dict[str, str]:
    key = f"authority-net:owner:{PATIENT}"
    return {key: attrs["b64_keyring"][key]}


def _read(client: TestClient, requester: str, keyring: dict[str, str]):
    return client.post(
        f"/records/{RECORD}/read",
        json={"requester_id": requester, "holder_keyring": keyring},
    )


def _unlock_payload(h: dict, *, shares=None, register_session: bool = True) -> dict:
    pki = h["pki"]
    shares = shares if shares is not None else h["shares"][:2]
    assertion = create_emergency_assertion(
        patient_id=PATIENT,
        clinician_id="dr-alice",
        facility_id="facility-a",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=pki["alice_priv"],
    )
    payload = {
        "assertion": assertion.model_dump(mode="json"),
        "clinician_certificate_pem": certificate_to_pem(pki["alice_cert"]).decode(),
        "facility_ca_certificate_pem": certificate_to_pem(pki["fa_cert"]).decode(),
        "trusted_root_certificate_pem": certificate_to_pem(
            pki["root"].certificate
        ).decode(),
        "shares": [(x, s.hex()) for x, s in shares],
        "pre_rewrap_key": pki["alice_pre_pub"],
        "lifecycle_signing_key_pem": private_key_to_pem(pki["life_priv"]).decode(),
        "correlation_id": f"corr-{secrets.token_hex(4)}",
    }
    if register_session:
        payload["baseline_wrapping_key_b64"] = base64.b64encode(
            secrets.token_bytes(32)
        ).decode()
        payload["emergency_duration_seconds"] = 60
    return payload


def _search(client: TestClient, term: str = "cardiac"):
    return client.post(
        f"/records/{RECORD}/emergency-search", json={"search_term": term}
    )


def _revoke_payload(h: dict, new_policy: PolicyTree, extra_keys: dict) -> dict:
    attrs = h["attrs"]
    old_dek = unwrap_dek_via_policy(
        h["ingested"].compiled_policy, attrs["attr_keyring"], h["ingested"].dek_wrapping
    )
    return {
        "actor_id": PATIENT,
        "actor_signing_key_pem": private_key_to_pem(h["pki"]["pat_priv"]).decode(),
        "old_dek_b64": base64.b64encode(old_dek).decode(),
        "new_clinical_policy": new_policy.model_dump(mode="json"),
        "owner_authority_id": "authority-net",
        "attribute_keyring": {**attrs["b64_keyring"], **extra_keys},
        "correlation_id": "corr-p51-revoke",
    }


_SURGEON_KEY = {
    "authority-med:role:surgeon": base64.b64encode(
        b"k_role_surgeon_32bytes_sample!!!"
    ).decode()
}
_SURGEON_ONLY = PolicyTree(
    node_type=PolicyNodeType.LEAF,
    attribute=Attribute(name="role", value="surgeon"),
    authority_id="authority-med",
)


# ---------------------------------------------------------------------------
# C1 -- revocation is cryptographic
# ---------------------------------------------------------------------------


@pytest.mark.claim("C1", level="system")
def test_c1_revoked_clinician_cannot_read_after_revoke_endpoint(hospital):
    """C1: after revocation through the API the excluded clinician reads nothing."""
    client, attrs = hospital["client"], hospital["attrs"]

    # Positive control: before revocation the clinician reads the record.
    before = _read(client, "dr-alice", _clinician_keyring(attrs))
    assert before.status_code == 200, before.text

    revoked = client.post(
        f"/records/{RECORD}/revoke",
        json=_revoke_payload(hospital, _SURGEON_ONLY, _SURGEON_KEY),
    )
    assert revoked.status_code == 200, revoked.text

    after = _read(client, "dr-alice", _clinician_keyring(attrs))
    assert after.status_code == 403
    assert "plaintext_b64" not in after.text

    # The owner leaf survives revocation: the patient still reads.
    assert _read(client, PATIENT, _owner_keyring(attrs)).status_code == 200


# ---------------------------------------------------------------------------
# C3 -- no single shareholder
# ---------------------------------------------------------------------------


@pytest.mark.claim("C3", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="F2/D1: the audit service releases share 3 to any caller that "
    "knows the record id -- no assertion, signature or one-time id is checked",
)
def test_c3_audit_service_releases_no_share_without_a_valid_assertion(audit_client):
    """C3: share 3 is not available to a caller presenting no emergency assertion.

    With share 1 held by the custodian, an unconditional share-3 release puts
    both shares in one actor's hands -- a single party opens the record.
    """
    client, _conn = audit_client
    registered = client.post(
        "/breakglass/shares",
        json={"share_key": RECORD, "x": 3, "share_hex": secrets.token_hex(33)},
    )
    assert registered.status_code == 201

    released = client.post(
        "/breakglass/release",
        json={
            "share_key": RECORD,
            "event_type": "breakglass_share_released",
            "event_data": {"record_id": RECORD},
            "actor_id": "anyone",
            "correlation_id": "corr-p51-c3",
        },
    )
    assert released.status_code in (400, 401, 403, 422)
    assert "share_hex" not in released.text


# ---------------------------------------------------------------------------
# C4 -- search dies with the emergency
# ---------------------------------------------------------------------------


@pytest.mark.claim("C4", level="system")
def test_c4_emergency_search_refused_after_expiry(hospital):
    """C4: once the session expires, the emergency-search endpoint refuses."""
    client = hospital["client"]
    assert (
        client.post(
            f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
        ).status_code
        == 200
    )

    # Positive control: search works while the emergency is open.
    live = _search(client)
    assert live.status_code == 200
    assert RECORD in live.json()["record_ids"]

    client.app.state.expiry_manager.expire_session(RECORD, force=True)

    dead = _search(client)
    assert dead.status_code == 403
    assert "record_ids" not in dead.text


@pytest.mark.claim("C4", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="F9/D3: expiry rotates nothing -- the pre-expiry shares re-open the "
    "record and re-derive the same search tokens",
)
def test_c4_pre_expiry_shares_do_not_restore_search(hospital):
    """C4: the capability that expired does not come back with the old shares."""
    client = hospital["client"]
    assert (
        client.post(
            f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
        ).status_code
        == 200
    )
    assert RECORD in _search(client).json()["record_ids"]

    client.app.state.expiry_manager.expire_session(RECORD, force=True)

    reopened = client.post(
        f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
    )
    if reopened.status_code == 200:
        result = _search(client)
        assert result.status_code != 200 or RECORD not in result.json()["record_ids"]


# ---------------------------------------------------------------------------
# C5 -- tamper-evident log
# ---------------------------------------------------------------------------


@pytest.mark.claim("C5", level="system")
def test_c5_tampered_db_row_fails_the_chain_verify_endpoint(audit_client):
    """C5: editing a committed audit row is caught by the service's own verify."""
    client, conn = audit_client
    appended = client.post(
        "/entries",
        json={
            "event_type": "record_read_granted",
            "event_data": {"record_id": RECORD},
            "actor_id": "facility-a",
            "correlation_id": "corr-p51-c5",
        },
    )
    assert appended.status_code == 200
    # Positive control: the untouched chain verifies.
    assert client.get("/chain/verify").json() == {"verified": True, "head_seq": 1}

    with conn.cursor() as cur:
        cur.execute(
            "UPDATE audit_log SET event_type = %s WHERE seq = %s",
            ("record_read_denied", 1),
        )

    verdict = client.get("/chain/verify")
    assert verdict.status_code == 409 or verdict.json()["verified"] is False


# ---------------------------------------------------------------------------
# C6 -- the state machine is enforced
# ---------------------------------------------------------------------------


@pytest.mark.claim("C6", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="F11/D7: the revoke handler writes REVOKED directly; it never checks "
    "the record's current state against LEGAL_TRANSITIONS",
)
def test_c6_api_refuses_revocation_of_an_emergency_open_record(hospital):
    """C6: EMERGENCY_OPEN -> REVOKED is not a legal transition, so the API refuses."""
    client, repo = hospital["client"], hospital["repo"]
    assert (
        client.post(
            f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
        ).status_code
        == 200
    )
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN

    response = client.post(
        f"/records/{RECORD}/revoke",
        json=_revoke_payload(hospital, _SURGEON_ONLY, _SURGEON_KEY),
    )
    assert response.status_code in (400, 403, 409)
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN


# ---------------------------------------------------------------------------
# C7 -- transitions are non-repudiable
# ---------------------------------------------------------------------------


@pytest.mark.claim("C7", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="D8/F11: the break-glass event is signed with a caller-supplied "
    "lifecycle key, not the clinician's key, so nobody can verify who opened it",
)
def test_c7_breakglass_event_verifies_against_the_clinicians_certificate(hospital):
    """C7: the EMERGENCY_OPEN event is attributable to the clinician who opened it."""
    client = hospital["client"]
    response = client.post(
        f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
    )
    assert response.status_code == 200

    event = TransitionEvent.model_validate(response.json()["transition_event"])
    assert event.actor_id == "dr-alice"
    verify_transition_event(event, hospital["pki"]["alice_pub"])


# ---------------------------------------------------------------------------
# C8 -- replay
# ---------------------------------------------------------------------------


@pytest.mark.claim("C8", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="F22: consumed assertion ids live in process memory, so a facility "
    "restart forgets them and the same assertion opens the record again",
)
def test_c8_replayed_assertion_rejected_after_facility_restart(hospital):
    """C8: replay protection survives a restart of the facility process."""
    payload = _unlock_payload(hospital, register_session=False)
    first = hospital["client"].post(f"/records/{RECORD}/breakglass", json=payload)
    assert first.status_code == 200

    # Same store, new process: the replay store and timer start empty.
    restarted = _hospital_app(hospital["repo"], hospital["pki"]["life_priv"])
    replay = restarted.post(f"/records/{RECORD}/breakglass", json=payload)
    assert replay.status_code == 400
    assert "rewrapped_dek_b64" not in replay.text


# ---------------------------------------------------------------------------
# C9 -- BOLA
# ---------------------------------------------------------------------------


@pytest.mark.claim("C9", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="F34/D5: read_record loads the record, wrapping and policy before any "
    "caller check, and requester_id is self-declared",
)
def test_c9_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db(
    hospital, monkeypatch
):
    """C9: an unauthorised caller is refused before the record is ever loaded."""
    client, repo, attrs = hospital["client"], hospital["repo"], hospital["attrs"]

    # Positive control: an authorised read succeeds.
    assert _read(client, "dr-alice", _clinician_keyring(attrs)).status_code == 200

    touched: list[str] = []
    for name in ("get_record", "get_wrapping_for_record", "get_compiled_policy"):
        real = getattr(repo, name)

        def spy(*args, _real=real, _name=name, **kwargs):
            touched.append(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(repo, name, spy)

    response = _read(client, "dr-mallory", {})
    assert response.status_code == 403
    assert touched == [], f"repository touched before authorization: {touched}"


# ---------------------------------------------------------------------------
# C10 -- credential lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.claim("C10", level="system")
@pytest.mark.xfail(
    strict=True,
    reason="F14: /attribute-keys/author releases any attribute key with no "
    "credential at all, so revocation and expiry are never consulted",
)
def test_c10_attribute_key_not_released_without_a_valid_credential():
    """C10: no attribute key leaves the authority without a valid credential."""
    client = TestClient(create_authority_app("authority-med", frozenset({"role"})))
    issued = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
        },
    )
    credential = issued.json()["credential"]

    # Positive control: a valid credential is exchanged for its key.
    assert (
        client.post(
            "/attribute-keys/release", json={"credential": credential}
        ).status_code
        == 200
    )

    revoked = client.post(f"/credentials/{credential['serial']}/revoke", json={})
    assert revoked.status_code == 200, revoked.text
    assert (
        client.post(
            "/attribute-keys/release", json={"credential": credential}
        ).status_code
        == 403
    )

    # The authoring path must not be a credential-free way round the refusal.
    authored = client.post(
        "/attribute-keys/author", json={"name": "role", "value": "physician"}
    )
    assert authored.status_code in (401, 403)
    assert "key_b64" not in authored.text
