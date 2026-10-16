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

import datetime
import os
import secrets
import uuid

import psycopg
import pytest
from api.audit_service import create_audit_app
from api.authority_service import create_authority_app
from api.hospital import create_hospital_app
from api.repository import InMemoryStorageRepository
from breakglass import create_emergency_assertion
from breakglass.assertion import clinical_context_digest
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts import TransitionEvent
from contracts.enums import LifecycleState, PolicyNodeType, ReasonCode
from contracts.policy import Attribute, PolicyTree
from crypto_core import InvalidSignatureError, certificate_to_pem, sign
from fastapi.testclient import TestClient
from identity.root_anchor import generate_root_anchor
from lifecycle import state_machine
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import create_transition_event, verify_transition_event
from records.ingest import ingest_record
from search.service import derive_search_token
from storage.migrate import apply_migrations

# PKI and attribute fixtures are shared with the API suite; the hospital
# fixture below is our own (it seeds the ingest-produced emergency wrapping).
from tests.api.conftest import (  # noqa: F401
    RecordingAuditSink,
    RecordingRotationPorts,
    attribute_materials,
    federation_pki,
    make_trust,
    signed_labels,
)
from tests.security.conftest import skip_or_fail_without_postgres
from tests.service_pki import PersonPKI, ServicePKI, release_body
from tests.transitions import open_event

RECORD = "rec-001"
PATIENT = "patient-001"
PLAINTEXT = b'{"diagnosis": "Coronary artery disease", "severity": "acute"}'
_DB_URL = os.environ.get("DATABASE_URL")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _seed(repo: InMemoryStorageRepository, attrs: dict, pki: dict) -> dict:
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
        clinical=signed_labels(pki, RECORD, PATIENT),
    )
    repo.insert_record(ingested.record)
    repo.insert_dek_wrapping(ingested.dek_wrapping)
    repo.insert_dek_wrapping(ingested.emergency_dek_wrapping)
    repo.store_compiled_policy(ingested.record.policy_id, ingested.compiled_policy)
    repo.upsert_lifecycle_state(record_id=RECORD, state=LifecycleState.GRANTED)
    for token in ingested.search_tokens.values():
        repo.insert_search_term(RECORD, token)
    repo.put_sealed_search_terms(RECORD, ingested.sealed_search_terms)
    return {
        "ingested": ingested,
        "em_key": em_key,
        "shares": split_emergency_key(em_key),
    }


def _hospital_app(
    repo: InMemoryStorageRepository, pki, rotation: RecordingRotationPorts
) -> TestClient:
    manager = EmergencyExpiryManager(
        signing_key=pki["life_priv"], default_duration_seconds=60.0
    )
    app = create_hospital_app(
        facility_id="facility-a",
        repository=repo,
        expiry_manager=manager,
        trust=make_trust(pki),
        audit_sink=RecordingAuditSink(),
        rotation_ports=rotation.ports,
    )
    # Signed as bootstrap, which every facility route allows (ADR-0066).
    return pki["services"].client(app, "facility-a")


@pytest.fixture()
def hospital(federation_pki, attribute_materials):  # noqa: F811
    repo = InMemoryStorageRepository()
    seeded = _seed(repo, attribute_materials, federation_pki)
    rotation = RecordingRotationPorts(attribute_materials["attr_keyring"])
    return {
        "repo": repo,
        "rotation": rotation,
        "client": _hospital_app(repo, federation_pki, rotation),
        "pki": federation_pki,
        "attrs": attribute_materials,
        **seeded,
    }


@pytest.fixture()
def audit_client(federation_pki):  # noqa: F811
    """A real audit service on Postgres (same pattern as tests/api), called
    as the custodian, which deposits and requests share 3."""
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
    app = create_audit_app(
        conn,
        actor_id="audit-p51",
        service_root=federation_pki["root"].certificate,
        trust=make_trust(federation_pki),
    )
    yield federation_pki["services"].client(
        app, "audit-service", caller="custodian"
    ), conn
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


def _unlock_payload(h: dict, *, shares=None) -> dict:
    """Dr Alice's open: her assertion and her own signed transition (ADR-0068)."""
    pki = h["pki"]
    shares = shares if shares is not None else h["shares"][:2]
    assertion = create_emergency_assertion(
        patient_id=PATIENT,
        clinician_id="dr-alice",
        facility_id="facility-a",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=pki["alice_priv"],
    )
    # Signed from the record's current state; a join ignores the event, so
    # an already open record gets one from GRANTED, which is never applied.
    state = h["repo"].get_lifecycle_state(RECORD)
    if state not in (LifecycleState.GRANTED, LifecycleState.REVOKED):
        state = LifecycleState.GRANTED
    event = open_event(
        RECORD, state, "dr-alice", ReasonCode.UNCONSCIOUS_PATIENT, pki["alice_priv"]
    )
    payload = {
        "assertion": assertion.model_dump(mode="json"),
        "clinician_certificate_pem": certificate_to_pem(pki["alice_cert"]).decode(),
        "shares": [(x, s.hex()) for x, s in shares],
        "pre_rewrap_key": pki["alice_pre_pub"],
        "transition_event": event.model_dump(mode="json"),
        "correlation_id": f"corr-{secrets.token_hex(4)}",
        "emergency_duration_seconds": 60,
    }
    return payload


def _rotated_shares(h: dict) -> list:
    """The shares the latest expiry rotation handed to the holders (ADR-0069)."""
    latest = h["rotation"].deposits[-1]
    return [latest["clinician_share"], latest["audit_share"]]


def _search(client: TestClient, term: str = "cardiac"):
    return client.post(
        f"/records/{RECORD}/emergency-search",
        json={"search_term": term, "requester_id": "dr-alice"},
    )


def _revoke_payload(h: dict, new_policy: PolicyTree) -> dict:
    """The patient's signed revocation (ADR-0080): no key, no DEK."""
    # The authority would author role:surgeon for the new tree.
    h["rotation"].keyring[("authority-med", "role", "surgeon")] = _SURGEON_KEY
    event = create_transition_event(
        record_id=RECORD,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=PATIENT,
        signing_key=h["pki"]["pat_priv"],
    )
    return {
        "transition_event": event.model_dump(mode="json"),
        "patient_certificate_pem": h["pki"]["pat_cert_pem"],
        "new_clinical_policy": new_policy.model_dump(mode="json"),
        "correlation_id": "corr-p51-revoke",
    }


_SURGEON_KEY = b"k_role_surgeon_32bytes_sample!!!"
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
        json=_revoke_payload(hospital, _SURGEON_ONLY),
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
def test_c3_audit_service_releases_no_share_without_a_valid_assertion(
    audit_client, federation_pki  # noqa: F811
):
    """C3: share 3 is not available to a caller presenting no emergency assertion.

    With share 1 held by the custodian, an unconditional share-3 release puts
    both shares in one actor's hands -- a single party opens the record. The
    audit service now validates the assertion itself (ADR-0067, D1-a): even
    the custodian, a caller allowed to ask, gets nothing without one.
    """
    client, _conn = audit_client
    registered = client.post(
        "/breakglass/shares",
        json={"share_key": RECORD, "x": 3, "share_hex": secrets.token_hex(33)},
    )
    assert registered.status_code == 201
    request = {
        "share_key": RECORD,
        "event_type": "breakglass_share_released",
        "event_data": {"record_id": RECORD},
        "actor_id": "anyone",
        "correlation_id": "corr-p51-c3",
    }

    released = client.post("/breakglass/release", json=request)
    assert released.status_code in (400, 401, 403, 422)
    assert "share_hex" not in released.text

    justification = "Unresponsive on arrival; medication history needed now."
    certificate_pem = certificate_to_pem(federation_pki["alice_cert"]).decode()

    def signed_for(record_id: str) -> dict:
        assertion = create_emergency_assertion(
            patient_id=PATIENT,
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=federation_pki["alice_priv"],
            clinical_context_digest=clinical_context_digest(
                record_id, justification, ""
            ),
        )
        return {
            **request,
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": certificate_pem,
            "justification": justification,
        }

    # A genuine assertion, but for another record, releases nothing either.
    elsewhere = client.post("/breakglass/release", json=signed_for("rec-other"))
    assert elsewhere.status_code == 403, elsewhere.text
    assert "share_hex" not in elsewhere.text

    # Positive control: with Dr Alice's assertion for this record it releases.
    allowed = client.post("/breakglass/release", json=signed_for(RECORD))
    assert allowed.status_code == 200, allowed.text


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
def test_c4_pre_expiry_shares_do_not_restore_search(hospital):
    """C4: the capability that expired does not come back with the old shares.

    Expiry runs the full rotation (ADR-0069, D3-a): a fresh DEK, policy root,
    emergency key and shares, and a search index re-derived under the new key.
    Review N6: a refusal alone proves nothing, so this shows all three sides --
    the old shares open nothing, the old token finds nothing, and the new
    shares (positive control) open the record with search working again.
    """
    client, repo = hospital["client"], hospital["repo"]
    assert (
        client.post(
            f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
        ).status_code
        == 200
    )
    assert RECORD in _search(client).json()["record_ids"]
    old_token = derive_search_token(hospital["em_key"], "cardiac")
    assert repo.find_records_by_search_term(old_token) == [RECORD]

    client.app.state.expiry_manager.expire_session(RECORD, force=True)
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED

    reopened = client.post(
        f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
    )
    assert reopened.status_code == 403, reopened.text
    assert "rewrapped_dek_b64" not in reopened.text
    # The token derived from the old emergency key matches nothing any more.
    assert repo.find_records_by_search_term(old_token) == []
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED

    # Positive control: the holders' new shares open the record, and search
    # under the new emergency key finds it again.
    fresh = client.post(
        f"/records/{RECORD}/breakglass",
        json=_unlock_payload(hospital, shares=_rotated_shares(hospital)),
    )
    assert fresh.status_code == 200, fresh.text
    assert RECORD in _search(client).json()["record_ids"]


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
def test_c6_api_refuses_revocation_of_an_emergency_open_record(hospital):
    """C6: EMERGENCY_OPEN -> REVOKED is not a legal transition, so the API refuses.

    The patient signs the revocation from the record's real state, so the
    state checks agree and only the transition rules stand in the way
    (ADR-0080): with them switched off (mutation C6a) the revocation would go
    through. ``create_transition_event`` refuses to sign an illegal pair, so
    the event is signed here directly over the canonical payload.
    """
    client, repo = hospital["client"], hospital["repo"]
    assert (
        client.post(
            f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
        ).status_code
        == 200
    )
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN

    body = _revoke_payload(hospital, _SURGEON_ONLY)
    body["transition_event"] = _illegal_revocation(hospital).model_dump(mode="json")
    response = client.post(f"/records/{RECORD}/revoke", json=body)

    assert response.status_code == 403
    assert "IllegalTransitionError" in response.json()["detail"]
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN


def _illegal_revocation(h: dict) -> TransitionEvent:
    """``EMERGENCY_OPEN -> REVOKED`` signed by the patient, bypassing the
    legality check that ``create_transition_event`` runs before signing."""
    event_id, nonce = uuid.uuid4(), secrets.token_bytes(16)
    issued_at = datetime.datetime.now(datetime.timezone.utc)
    fields = {
        "event_id": event_id,
        "record_id": RECORD,
        "from_state": LifecycleState.EMERGENCY_OPEN,
        "to_state": LifecycleState.REVOKED,
        "actor_id": PATIENT,
        "reason_code": None,
        "issued_at": issued_at,
        "nonce": nonce,
    }
    signature = sign(h["pki"]["pat_priv"], state_machine._canonical_payload(**fields))
    return TransitionEvent(**fields, signature=signature)


# ---------------------------------------------------------------------------
# C7 -- transitions are non-repudiable
# ---------------------------------------------------------------------------


@pytest.mark.claim("C7", level="system")
def test_c7_breakglass_event_verifies_against_the_clinicians_certificate(hospital):
    """C7: the EMERGENCY_OPEN event is attributable to the clinician who opened it.

    The custodian signs it with the clinician's own key (ADR-0068, D8-a); the
    facility verifies it against the clinician's certificate before anything
    opens, and refuses an event signed with any other key.
    """
    client = hospital["client"]
    response = client.post(
        f"/records/{RECORD}/breakglass", json=_unlock_payload(hospital)
    )
    assert response.status_code == 200

    event = TransitionEvent.model_validate(response.json()["transition_event"])
    assert event.actor_id == "dr-alice"
    verify_transition_event(event, hospital["pki"]["alice_pub"])
    assert hospital["repo"].get_transition_event(str(event.event_id)) == event
    # Attributable to her alone: it does not verify under any other key.
    with pytest.raises(InvalidSignatureError):
        verify_transition_event(event, hospital["pki"]["bob_pub"])


@pytest.mark.claim("C7", level="system")
def test_c7_an_event_not_signed_by_the_clinician_opens_nothing(hospital):
    """C7: a transition signed with any key but the clinician's is refused."""
    client, repo = hospital["client"], hospital["repo"]
    payload = _unlock_payload(hospital)
    forged = open_event(
        RECORD,
        LifecycleState.GRANTED,
        "dr-alice",
        ReasonCode.UNCONSCIOUS_PATIENT,
        hospital["pki"]["life_priv"],
    )
    response = client.post(
        f"/records/{RECORD}/breakglass",
        json={**payload, "transition_event": forged.model_dump(mode="json")},
    )
    assert response.status_code == 400, response.text
    assert "rewrapped_dek_b64" not in response.text
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    assert repo.transition_events == {}


# ---------------------------------------------------------------------------
# C8 -- replay
# ---------------------------------------------------------------------------


@pytest.mark.claim("C8", level="system")
def test_c8_replayed_assertion_rejected_after_facility_restart(hospital):
    """C8: replay protection survives a restart of the facility process."""
    payload = _unlock_payload(hospital)
    first = hospital["client"].post(f"/records/{RECORD}/breakglass", json=payload)
    assert first.status_code == 200

    # Same store, new process: the replay store and timer start empty.
    restarted = _hospital_app(hospital["repo"], hospital["pki"], hospital["rotation"])
    replay = restarted.post(f"/records/{RECORD}/breakglass", json=payload)
    assert replay.status_code == 400
    assert "rewrapped_dek_b64" not in replay.text


# ---------------------------------------------------------------------------
# C9 -- BOLA
# ---------------------------------------------------------------------------


@pytest.mark.claim("C9", level="system")
def test_c9_bola_authenticated_but_unauthorised_caller_denied_before_crypto_or_db(
    hospital, monkeypatch
):
    """C9: an unauthorised caller is refused before the record is ever loaded.

    Every caller is an authenticated federation service (ADR-0066, D5-a). Two
    unauthorised cases reach the facility: a service of a kind that may not
    read records at all (the portal), and an authenticated key agent asking
    for a requester who presents no key. Both are refused before the record,
    its wrapping or its policy is touched (review F34).
    """
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

    portal = hospital["pki"]["services"].client(
        client.app, "facility-a", caller="portal"
    )
    by_portal = _read(portal, "dr-alice", _clinician_keyring(attrs))
    assert by_portal.status_code == 403
    assert "plaintext_b64" not in by_portal.text

    custodian = hospital["pki"]["services"].client(
        client.app, "facility-a", caller="custodian"
    )
    response = _read(custodian, "dr-mallory", {})
    assert response.status_code == 403
    assert touched == [], f"repository touched before authorization: {touched}"

    unsigned = TestClient(client.app).post(
        f"/records/{RECORD}/read",
        json={"requester_id": "dr-alice", "holder_keyring": _clinician_keyring(attrs)},
    )
    assert unsigned.status_code == 401
    assert touched == [], f"repository touched before authorization: {touched}"


# ---------------------------------------------------------------------------
# C10 -- credential lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.claim("C10", level="system")
def test_c10_attribute_key_not_released_without_a_valid_credential():
    """C10: no attribute key leaves the authority without a valid credential.

    The authoring path takes only a signed request from a policy-sealing
    service (ADR-0066, replacing the F14 interim address allowlist); those
    services are trusted parties by construction (ADR-0026).
    """
    services = ServicePKI(generate_root_anchor())
    people = PersonPKI(services.root)
    alice = people.clinician("dr-alice")
    app = create_authority_app(
        "authority-med",
        frozenset({"role"}),
        service_root=services.root.certificate,
        subject_trust=people.trust,
    )
    client = services.client(app, "authority-med")
    issued = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
        },
    )
    credential = issued.json()["credential"]

    # Positive control: a valid credential, asked for by its subject (ADR-0082),
    # is exchanged for its key.
    assert (
        client.post(
            "/attribute-keys/release", json=release_body(credential, alice)
        ).status_code
        == 200
    )

    # A copy of the valid credential, presented by someone else, gets nothing
    # (review F15).
    mallory = people.clinician("dr-mallory")
    copied = client.post(
        "/attribute-keys/release", json=release_body(credential, mallory)
    )
    assert copied.status_code == 403
    assert "key_b64" not in copied.text

    revoked = client.post(f"/credentials/{credential['serial']}/revoke", json={})
    assert revoked.status_code == 200, revoked.text
    assert (
        client.post(
            "/attribute-keys/release", json=release_body(credential, alice)
        ).status_code
        == 403
    )

    # The authoring path must not be a credential-free way round the refusal.
    for outsider in (
        TestClient(app),
        services.client(app, "authority-med", caller="portal"),
    ):
        authored = outsider.post(
            "/attribute-keys/author", json={"name": "role", "value": "physician"}
        )
        assert authored.status_code in (401, 403)
        assert "key_b64" not in authored.text
