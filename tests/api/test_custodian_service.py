"""Tests for the Key Custodian Service (ADR-0043, C14).

A miniature federation runs in-process -- two real authority services, one
real facility node on an in-memory repository, and a stub audit service that
implements the ``/breakglass/release`` commit-then-release contract -- all
reachable from the custodian through an ``httpx.MockTransport`` that routes
by hostname. No Postgres needed.

The negative cases here are the evidence for the portal boundary
(ADR-0014/0021, P4-7/P4-8a "Done when"):

- a subject with no deposited material can sign nothing and read nothing;
- a patient whose ``owner:<patient_id>`` credential is absent is refused by
  the facility's policy engine (ADR-0016 fail-closed);
- break-glass fails closed when the audit service cannot commit -- no share
  3, no unlock, the record stays GRANTED.
"""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest
from api.authority_service import SubjectTrust, create_authority_app
from api.custodian_service import (
    CustodianEndpoints,
    CustodianVault,
    create_custodian_app,
)
from api.hospital import FacilityTrust, create_hospital_app
from api.repository import InMemoryStorageRepository
from api.service_auth import CERTIFICATE_HEADER, ENVELOPE_HEADER
from audit.chain import build_entry, create_genesis_entry
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts import TransitionEvent
from contracts.clinical import ClinicalMetadata
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_to_pem,
    generate_ec_keypair,
    private_key_to_pem,
    public_key_to_pem,
)
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
    issue_patient_certificate,
)
from identity.root_anchor import generate_root_anchor
from lifecycle.expiry import EmergencyExpiryManager
from lifecycle.state_machine import verify_transition_event
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.ingest import ingest_record
from records.labels import sign_clinical_labels

from tests.api.conftest import RecordingAuditSink, RecordingRotationPorts
from tests.service_pki import ServicePKI

AUTH_MED = "http://authority-med"
AUTH_NET = "http://authority-net"
FACILITY_A = "http://facility-a"
FACILITY_B = "http://facility-b"
AUDIT = "http://audit"

PATIENT = "pat-101"
DOC_CARDIO = "doc-201"  # physician + cardiology at facility-a
DOC_ER = "doc-301"  # emergency-physician at facility-b
RECORD = "rec-001"
PLAINTEXT = b'{"diagnosis": "Acute MI", "allergies": ["Penicillin"]}'


def _audit_stub(
    shares: dict[str, tuple[int, bytes]],
    *,
    commit_ok: bool = True,
    deposit_ok: bool = True,
) -> FastAPI:
    """Stand-in for ``api.audit_service`` without Postgres.

    Honours the properties the custodian relies on: the share is released
    only when the commit succeeded (``commit_ok``), otherwise 503 and nothing;
    a share is never overwritten (409, review F4); ``deposit_ok=False`` makes
    every deposit fail with 503.
    """
    app = FastAPI()
    signing_key, public_key = generate_ec_keypair()
    head = create_genesis_entry(signing_key=signing_key)
    state: dict[str, Any] = {"seq": 0, "entries": [], "head": head}

    def _signed(payload: dict[str, Any]) -> dict[str, Any]:
        # Entries are signed like the real service's, so the custodian's
        # release check (review F31) has something genuine to verify.
        entry = build_entry(
            head=state["head"],
            event_type=payload.get("event_type", "breakglass_share_release"),
            event_data=payload.get("event_data", {}),
            actor_id=payload["actor_id"],
            correlation_id=payload["correlation_id"],
            signing_key=signing_key,
        )
        state["head"] = entry
        state["seq"] = entry.seq
        state["entries"].append({**payload, "seq": entry.seq})
        return entry.model_dump(mode="json")

    @app.post("/entries")
    def entries(payload: dict[str, Any]) -> dict[str, Any]:
        return {"entry": _signed(payload)}

    @app.post("/breakglass/shares")
    def deposit(payload: dict[str, Any]) -> dict[str, Any]:
        if not deposit_ok:
            raise HTTPException(status_code=503, detail="audit service unavailable")
        if payload["share_key"] in shares:
            raise HTTPException(status_code=409, detail="share already held")
        shares[payload["share_key"]] = (
            payload["x"],
            bytes.fromhex(payload["share_hex"]),
        )
        return {"status": "registered", "share_key": payload["share_key"]}

    @app.post("/breakglass/release")
    def release(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["share_key"] not in shares:
            raise HTTPException(status_code=404, detail="no share held")
        if not commit_ok:
            raise HTTPException(
                status_code=503, detail="log commit failed; share was not released"
            )
        entry = _signed(payload)
        x, share = shares[payload["share_key"]]
        return {"x": x, "share_hex": share.hex(), "entry": entry}

    app.state.log = state
    app.state.public_key_pem = public_key_to_pem(public_key).decode("ascii")
    return app


def _forwarded(request: httpx.Request) -> dict[str, str]:
    """The headers an in-process service needs: body type plus the signed
    request envelope and service certificate (ADR-0066)."""
    headers = {"content-type": "application/json"}
    for name in (ENVELOPE_HEADER, CERTIFICATE_HEADER):
        if name in request.headers:
            headers[name] = request.headers[name]
    return headers


def _router(
    apps: dict[str, FastAPI], seen: list[httpx.Request] | None = None
) -> httpx.Client:
    """An httpx client whose transport dispatches by hostname to in-process apps.

    ``seen`` collects every request sent, for tests that inspect the wire.
    """
    # Requests arrive signed by the custodian; the headers are forwarded as is.
    clients = {host: TestClient(app) for host, app in apps.items()}

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        host = urlparse(str(request.url)).hostname or ""
        client = clients[host]
        resp = client.request(
            request.method,
            request.url.raw_path.decode("ascii"),
            content=request.content,
            headers=_forwarded(request),
        )
        return httpx.Response(resp.status_code, content=resp.content)

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture()
def federation():
    """Two authorities, two facilities, an audit stub, one ingested record."""
    root = generate_root_anchor()
    fa_priv, fa_pub = generate_ec_keypair()
    fa_cert = issue_facility_ca_certificate(root, "facility-a", fa_pub)
    fb_priv, fb_pub = generate_ec_keypair()
    fb_cert = issue_facility_ca_certificate(root, "facility-b", fb_pub)

    # Every service takes signed requests only (ADR-0066); seeding signs as
    # bootstrap, the custodian as itself.
    services = ServicePKI(root)
    # Subjects prove possession under their facility CAs (ADR-0074).
    subject_trust = SubjectTrust(
        root=root.certificate,
        facility_cas={"facility-a": fa_cert, "facility-b": fb_cert},
    )
    app_med = create_authority_app(
        "authority-med",
        frozenset({"role"}),
        service_root=root.certificate,
        subject_trust=subject_trust,
    )
    app_net = create_authority_app(
        "authority-net",
        frozenset({"specialty", "facility", "owner"}),
        service_root=root.certificate,
        subject_trust=subject_trust,
    )
    med = services.client(app_med, "authority-med")
    net = services.client(app_net, "authority-net")

    def issue(client: TestClient, subject: str, name: str, value: str, **kw: Any):
        r = client.post(
            "/credentials/issue",
            json={
                "subject_id": subject,
                "attribute": {"name": name, "value": value},
                **kw,
            },
        )
        assert r.status_code == 201, r.text
        return r.json()["credential"]

    creds = {
        DOC_CARDIO: [
            issue(med, DOC_CARDIO, "role", "physician"),
            issue(net, DOC_CARDIO, "specialty", "cardiology"),
        ],
        DOC_ER: [issue(med, DOC_ER, "role", "emergency-physician")],
        PATIENT: [issue(net, PATIENT, "owner", PATIENT, owner=True)],
    }

    def author_key(client: TestClient, name: str, value: str) -> bytes:
        r = client.post("/attribute-keys/author", json={"name": name, "value": value})
        assert r.status_code == 200, r.text
        return base64.b64decode(r.json()["key_b64"])

    keyring = {
        ("authority-med", "role", "physician"): author_key(med, "role", "physician"),
        ("authority-net", "specialty", "cardiology"): author_key(
            net, "specialty", "cardiology"
        ),
        ("authority-net", "owner", PATIENT): author_key(net, "owner", PATIENT),
    }
    policy = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="role", value="physician"),
                authority_id="authority-med",
            ),
            PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="specialty", value="cardiology"),
                authority_id="authority-net",
            ),
        ),
    )

    # The patient, certified by their home facility (ADR-0064), signs the
    # record's labels as the custodian does at upload.
    pat_priv, pat_pub = generate_ec_keypair()
    pat_cert_pem = certificate_to_pem(
        issue_patient_certificate(fa_priv, fa_cert, PATIENT, pat_pub)
    ).decode("ascii")

    em_key = generate_emergency_key()
    share1, share2, share3 = split_emergency_key(em_key)
    ingest = ingest_record(
        plaintext=PLAINTEXT,
        patient_id=PATIENT,
        facility_id="facility-a",
        owner_authority_id="authority-net",
        clinical_policy=policy,
        attribute_keyring=keyring,
        search_terms=["cardiac"],
        emergency_key=em_key,
        record_id=RECORD,
        clinical=sign_clinical_labels(
            ClinicalMetadata(),
            record_id=RECORD,
            patient_id=PATIENT,
            signing_key=pat_priv,
            certificate_pem=pat_cert_pem,
        ),
    )
    repo = InMemoryStorageRepository()
    repo.insert_record(ingest.record)
    repo.insert_dek_wrapping(ingest.dek_wrapping)
    assert ingest.emergency_dek_wrapping is not None
    repo.insert_dek_wrapping(ingest.emergency_dek_wrapping)
    repo.store_compiled_policy(ingest.record.policy_id, ingest.compiled_policy)
    repo.upsert_lifecycle_state(record_id=RECORD, state=LifecycleState.GRANTED)
    repo.put_sealed_search_terms(RECORD, ingest.sealed_search_terms)
    rotation = RecordingRotationPorts(keyring)

    life_priv, _ = generate_ec_keypair()
    expiry = EmergencyExpiryManager(signing_key=life_priv, default_duration_seconds=60)
    trust = FacilityTrust(
        root=root.certificate,
        facility_cas={"facility-a": fa_cert, "facility-b": fb_cert},
    )
    audit_sink = RecordingAuditSink()
    expiry_a = EmergencyExpiryManager(
        signing_key=life_priv, default_duration_seconds=60
    )
    app_fa = create_hospital_app(
        "facility-a",
        repository=repo,
        trust=trust,
        audit_sink=audit_sink,
        expiry_manager=expiry_a,
        rotation_ports=rotation.ports,
    )
    app_fb = create_hospital_app(
        "facility-b",
        repository=repo,
        expiry_manager=expiry,
        trust=trust,
        audit_sink=audit_sink,
        rotation_ports=rotation.ports,
    )

    # Clinician identities: certs from their facility CA, PRE keypairs.
    cardio_priv, cardio_pub = generate_ec_keypair()
    cardio_cert = issue_clinician_certificate(fa_priv, fa_cert, DOC_CARDIO, cardio_pub)
    er_priv, er_pub = generate_ec_keypair()
    er_cert = issue_clinician_certificate(fb_priv, fb_cert, DOC_ER, er_pub)
    er_pre_priv, er_pre_pub = generate_pre_keypair()

    return {
        "apps": {
            "authority-med": app_med,
            "authority-net": app_net,
            "facility-a": app_fa,
            "facility-b": app_fb,
        },
        "repo": repo,
        "record": ingest.record,
        "services": services,
        "root_cert": root.certificate,
        "rotation": rotation,
        "expiry_a": expiry_a,
        "er_pub": er_pub,
        "shares": {"share1": share1, "share2": share2, "share3": share3},
        "creds": creds,
        "root_pem": certificate_to_pem(root.certificate).decode("ascii"),
        "fa_pem": certificate_to_pem(fa_cert).decode("ascii"),
        "fb_pem": certificate_to_pem(fb_cert).decode("ascii"),
        "material": {
            DOC_CARDIO: {
                "kind": "clinician",
                "facility_id": "facility-a",
                "signing_key_pem": private_key_to_pem(cardio_priv).decode("ascii"),
                "certificate_pem": certificate_to_pem(cardio_cert).decode("ascii"),
                "credentials": creds[DOC_CARDIO],
            },
            DOC_ER: {
                "kind": "clinician",
                "facility_id": "facility-b",
                "signing_key_pem": private_key_to_pem(er_priv).decode("ascii"),
                "certificate_pem": certificate_to_pem(er_cert).decode("ascii"),
                "pre_private_key": er_pre_priv,
                "pre_public_key": er_pre_pub,
                "credentials": creds[DOC_ER],
            },
            PATIENT: {
                "kind": "patient",
                "signing_key_pem": private_key_to_pem(pat_priv).decode("ascii"),
                "certificate_pem": pat_cert_pem,
                "credentials": creds[PATIENT],
            },
        },
    }


def _custodian(
    federation: dict[str, Any],
    *,
    audit_commit_ok: bool = True,
    audit_deposit_ok: bool = True,
    seen: list[httpx.Request] | None = None,
) -> TestClient:
    audit_shares = {RECORD: federation["shares"]["share3"]}
    audit = _audit_stub(
        audit_shares,
        commit_ok=audit_commit_ok,
        deposit_ok=audit_deposit_ok,
    )
    http = _router({**federation["apps"], "audit": audit}, seen)
    app = create_custodian_app(
        endpoints=CustodianEndpoints(
            authorities={"authority-med": AUTH_MED, "authority-net": AUTH_NET},
            facilities={"facility-a": FACILITY_A, "facility-b": FACILITY_B},
            audit=AUDIT,
        ),
        http_client=http,
        identity=federation["services"].identity("custodian"),
        service_root=federation["root_cert"],
        state_loader=federation["repo"].get_lifecycle_state,
        record_loader=federation["repo"].get_record,
        root_certificate_pem=federation["root_pem"],
        audit_public_key_pem=audit.state.public_key_pem,
        facility_ca_certificate_pems={
            "facility-a": federation["fa_pem"],
            "facility-b": federation["fb_pem"],
        },
    )
    client = federation["services"].client(app, "custodian")
    client.app_audit = audit  # type: ignore[attr-defined]
    client.app_audit_shares = audit_shares  # type: ignore[attr-defined]
    return client


def _deposit_all(client: TestClient, federation: dict[str, Any]) -> None:
    for subject_id, material in federation["material"].items():
        r = client.post(f"/subjects/{subject_id}/material", json=material)
        assert r.status_code == 201, r.text
    x, share = federation["shares"]["share1"]
    r = client.post(
        f"/records/{RECORD}/shares", json={"x": x, "share_hex": share.hex()}
    )
    assert r.status_code == 201, r.text


# --- Read-back never leaks a key ----------------------------------------------


def test_subject_summary_describes_keys_without_returning_them(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    body = client.get(f"/subjects/{DOC_CARDIO}").json()
    assert body["kind"] == "clinician"
    assert "BEGIN PUBLIC KEY" in body["public_key_pem"]
    assert {(c["name"], c["value"]) for c in body["credentials"]} == {
        ("role", "physician"),
        ("specialty", "cardiology"),
    }
    assert "PRIVATE" not in json.dumps(body)


def test_unknown_subject_is_404_everywhere(federation):
    client = _custodian(federation)
    assert client.get("/subjects/nobody").status_code == 404
    r = client.post(
        "/subjects/nobody/read", json={"record_id": RECORD, "facility_id": "facility-a"}
    )
    assert r.status_code == 404
    assert "grants nothing" in r.json()["detail"]


# --- Owner self-access (ADR-0016) --------------------------------------------


def test_patient_reads_own_record_via_owner_leaf(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{PATIENT}/read",
        json={
            "record_id": RECORD,
            "facility_id": "facility-a",
            "correlation_id": "c-1",
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert base64.b64decode(body["plaintext_b64"]) == PLAINTEXT
    assert body["access_via"] == "owner"
    assert body["attributes_presented"] == [f"authority-net:owner:{PATIENT}"]


@pytest.mark.claim("C11", level="system")
def test_patient_without_owner_credential_is_refused(federation):
    """ADR-0016 / P5-1: a login alone, with no owner attribute, decrypts nothing."""
    client = _custodian(federation)
    material = dict(federation["material"][PATIENT], credentials=[])
    assert (
        client.post(f"/subjects/{PATIENT}/material", json=material).status_code == 201
    )
    r = client.post(
        f"/subjects/{PATIENT}/read",
        json={"record_id": RECORD, "facility_id": "facility-a"},
    )
    assert r.status_code == 403
    assert "Policy denied" in r.json()["detail"]
    assert "plaintext" not in r.text


def test_authority_outage_is_distinct_from_a_policy_denial(federation):
    """Finding #2: an authority being down must not masquerade as a denial.

    If the custodian silently dropped a credential whose authority was
    unreachable, a legitimately-authorised clinician would receive a 403
    "Policy denied" and triage would hunt an authorisation bug instead of an
    outage. The custodian must fail closed with a *distinguishable* 502 instead.
    """
    down = FastAPI()

    @down.post("/attribute-keys/release")
    def _release(payload: dict[str, Any]) -> dict[str, Any]:
        raise HTTPException(status_code=503, detail="authority-med under maintenance")

    audit = _audit_stub({RECORD: federation["shares"]["share3"]})
    http = _router({**federation["apps"], "authority-med": down, "audit": audit})
    app = create_custodian_app(
        endpoints=CustodianEndpoints(
            authorities={"authority-med": AUTH_MED, "authority-net": AUTH_NET},
            facilities={"facility-a": FACILITY_A, "facility-b": FACILITY_B},
            audit=AUDIT,
        ),
        http_client=http,
        identity=federation["services"].identity("custodian"),
        service_root=federation["root_cert"],
        state_loader=federation["repo"].get_lifecycle_state,
        record_loader=federation["repo"].get_record,
        root_certificate_pem=federation["root_pem"],
        audit_public_key_pem=audit.state.public_key_pem,
    )
    client = federation["services"].client(app, "custodian")
    _deposit_all(client, federation)

    # DOC_CARDIO needs role:physician from the (now down) authority-med.
    r = client.post(
        f"/subjects/{DOC_CARDIO}/read",
        json={"record_id": RECORD, "facility_id": "facility-a"},
    )
    assert r.status_code == 502, r.text
    detail = r.json()["detail"]
    assert "authority-med" in detail
    assert "not a policy denial" in detail
    assert "Policy denied" not in detail


# --- Consent (ADR-0014 request-then-approve, ADR-0031 gate) -------------------


def test_consent_round_trip_signs_request_grant_and_revocation(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)

    r = client.post(
        f"/subjects/{DOC_CARDIO}/consent/request",
        json={"patient_id": PATIENT, "scope": [RECORD], "purpose": "pre-op review"},
    )
    assert r.status_code == 200, r.text
    request = r.json()["request"]
    assert request["requester_id"] == DOC_CARDIO

    # A clinician cannot decide on the patient's behalf.
    r = client.post(
        f"/subjects/{DOC_CARDIO}/consent/decide",
        json={"request": request, "status": "granted"},
    )
    assert r.status_code == 403

    r = client.post(
        f"/subjects/{PATIENT}/consent/decide",
        json={"request": request, "status": "granted"},
    )
    assert r.status_code == 200, r.text
    grant = r.json()["grant"]
    cert_pem = r.json()["patient_certificate_pem"]
    assert grant["status"] == "granted"

    # The facility verifies the patient signature and stores the grant.
    fa = federation["services"].client(
        federation["apps"]["facility-a"], "facility-a", caller="portal"
    )
    r = fa.post(
        "/consent/grants",
        json={"grant": grant, "patient_certificate_pem": cert_pem},
    )
    assert r.status_code == 200, r.text

    # Reading under the grant works for a clinician who also satisfies policy.
    r = client.post(
        f"/subjects/{DOC_CARDIO}/read",
        json={"record_id": RECORD, "facility_id": "facility-a", "grant": grant},
    )
    assert r.status_code == 200, r.text
    assert r.json()["access_via"] == "consent"
    assert base64.b64decode(r.json()["plaintext_b64"]) == PLAINTEXT

    # Revocation is patient-signed; the revoked grant is refused at read time.
    r = client.post(f"/subjects/{PATIENT}/consent/revoke", json={"prior_grant": grant})
    assert r.status_code == 200, r.text
    revoked = r.json()["grant"]
    assert revoked["status"] == "revoked"
    r = client.post(
        f"/subjects/{DOC_CARDIO}/read",
        json={"record_id": RECORD, "facility_id": "facility-a", "grant": revoked},
    )
    assert r.status_code == 403
    assert "revoked" in r.json()["detail"].lower()


def test_consent_does_not_bypass_policy(federation):
    """ADR-0031: consent is a gate on top of the policy tree, not a replacement."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    request = client.post(
        f"/subjects/{DOC_ER}/consent/request",
        json={"patient_id": PATIENT, "scope": [RECORD], "purpose": "follow-up"},
    ).json()["request"]
    grant = client.post(
        f"/subjects/{PATIENT}/consent/decide",
        json={"request": request, "status": "granted"},
    ).json()["grant"]
    # The ER physician holds no cardiology attribute -> policy denies.
    r = client.post(
        f"/subjects/{DOC_ER}/read",
        json={"record_id": RECORD, "facility_id": "facility-b", "grant": grant},
    )
    assert r.status_code == 403
    assert "Policy denied" in r.json()["detail"]


# --- Break-glass (ARCHITECTURE §5 steps 1-5) -----------------------------------


def test_breakglass_unlocks_with_clinician_and_audit_shares(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={
            "patient_id": PATIENT,
            "record_id": RECORD,
            "reason_code": "unconscious_patient",
            "correlation_id": "corr-bg-1",
            "emergency_duration_seconds": 30,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["facility_id"] == "facility-a"  # Home node owns the shared timer.
    assert body["transition_event"]["to_state"] == "emergency_open"
    # C7 (ADR-0068): the event is the clinician's, verifiable by their key.
    event = TransitionEvent.model_validate(body["transition_event"])
    assert event.actor_id == DOC_ER
    verify_transition_event(event, federation["er_pub"])
    assert [s["holder"] for s in body["shares_presented"]] == [
        "clinician",
        "audit-service",
    ]
    assert body["shares_presented"][1]["audit_entry_seq"] == 1
    assert base64.b64decode(body["plaintext_b64"]) == PLAINTEXT
    assert body["expires_at"] is not None
    assert (
        federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.EMERGENCY_OPEN
    )

    # The share-release entry was committed before the unlock, with metadata only.
    entry = client.app_audit.state.log["entries"][0]  # type: ignore[attr-defined]
    assert entry["event_type"] == "breakglass_share_released"
    assert entry["event_data"]["assertion_id"] == body["assertion_id"]
    assert "share" not in json.dumps(entry["event_data"]).lower()


def test_second_viewer_naming_another_facility_joins_at_the_record_node(federation):
    """ADR-0061: a clinician elsewhere is routed to the node holding the session."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    body = {
        "patient_id": PATIENT,
        "record_id": RECORD,
        "reason_code": "sepsis",
        "emergency_duration_seconds": 30,
    }
    first = client.post(f"/subjects/{DOC_ER}/breakglass", json=body)
    assert first.status_code == 200, first.text
    second = client.post(
        f"/subjects/{DOC_ER}/breakglass", json={**body, "facility_id": "facility-b"}
    )
    assert second.status_code == 200, second.text
    assert second.json()["facility_id"] == "facility-a"
    assert second.json()["joined"] is True
    assert second.json()["expires_at"] == first.json()["expires_at"]


def test_breakglass_fails_closed_when_audit_cannot_commit(federation):
    """No log entry, no share 3, no unlock -- the record stays GRANTED."""
    client = _custodian(federation, audit_commit_ok=False)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"},
    )
    assert r.status_code == 503
    assert "share was not released" in r.json()["detail"]
    assert federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED


def test_breakglass_needs_clinician_custody_share(federation):
    client = _custodian(federation)
    for subject_id, material in federation["material"].items():
        client.post(f"/subjects/{subject_id}/material", json=material)
    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"},
    )
    assert r.status_code == 404
    assert "threshold cannot be met" in r.json()["detail"]
    assert federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED


def test_patient_cannot_declare_breakglass(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{PATIENT}/breakglass",
        json={"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"},
    )
    assert r.status_code == 403


def test_breakglass_never_puts_the_clinician_key_on_the_wire(federation):
    """ADR-0043 invariant: a subject's own signing key never leaves the custodian.

    The clinician's ECDSA key signs the EmergencyAssertion and the
    EMERGENCY_OPEN transition *inside* the custodian (ADR-0068) and only the
    signed artefacts go upstream. So the clinician's private key must appear
    in no request body -- and no header -- the custodian sends to any
    facility, authority or the audit service. This is the outbound
    counterpart of ``test_subject_summary_describes_keys_without_returning_them``
    and the regression guard for the finding that the break-glass path used to
    forward ``material.signing_key`` as ``lifecycle_signing_key_pem``.
    """
    captured: list[bytes] = []
    audit = _audit_stub({RECORD: federation["shares"]["share3"]})
    apps = {**federation["apps"], "audit": audit}
    # Each in-process service sees the custodian as an allowlisted caller.
    clients = {host: TestClient(app) for host, app in apps.items()}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.content)
        captured.append(str(request.headers).encode("utf-8"))
        host = urlparse(str(request.url)).hostname or ""
        resp = clients[host].request(
            request.method,
            request.url.raw_path.decode("ascii"),
            content=request.content,
            headers=_forwarded(request),
        )
        return httpx.Response(resp.status_code, content=resp.content)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    app = create_custodian_app(
        endpoints=CustodianEndpoints(
            authorities={"authority-med": AUTH_MED, "authority-net": AUTH_NET},
            facilities={"facility-a": FACILITY_A, "facility-b": FACILITY_B},
            audit=AUDIT,
        ),
        http_client=http,
        identity=federation["services"].identity("custodian"),
        service_root=federation["root_cert"],
        state_loader=federation["repo"].get_lifecycle_state,
        record_loader=federation["repo"].get_record,
        root_certificate_pem=federation["root_pem"],
        audit_public_key_pem=audit.state.public_key_pem,
        facility_ca_certificate_pems={
            "facility-a": federation["fa_pem"],
            "facility-b": federation["fb_pem"],
        },
    )
    client = federation["services"].client(app, "custodian")
    _deposit_all(client, federation)  # deposits go INTO the custodian, not captured

    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"},
    )
    assert r.status_code == 200, r.text
    assert captured, "the custodian made no upstream calls"

    # The clinician key's base64 body lines are unaffected by JSON escaping, so
    # they would appear verbatim in any body that carried the key.
    er_pem = federation["material"][DOC_ER]["signing_key_pem"]
    key_lines = [
        ln for ln in er_pem.splitlines() if "PRIVATE KEY" not in ln and len(ln) > 20
    ]
    assert key_lines
    for body in captured:
        text = body.decode("utf-8", "replace")
        for line in key_lines:
            assert line not in text, "clinician signing key leaked to an upstream call"


# --- Patient upload (P3-14 ingest through the key agent) -----------------------

CARDIO_POLICY = {
    "node_type": "and",
    "children": [
        {
            "node_type": "leaf",
            "attribute": {"name": "role", "value": "physician"},
            "authority_id": "authority-med",
        },
        {
            "node_type": "leaf",
            "attribute": {"name": "specialty", "value": "cardiology"},
            "authority_id": "authority-net",
        },
    ],
}


def _upload(client: TestClient, content: bytes, **extra: Any) -> Any:
    body = {
        "facility_id": "facility-a",
        "content_b64": base64.b64encode(content).decode("ascii"),
        "content_type": "text/plain",
        "clinical_policy": CARDIO_POLICY,
        "search_terms": ["echo", "stress-test"],
        **extra,
    }
    return client.post(f"/subjects/{PATIENT}/records", json=body)


def test_patient_upload_is_sealed_with_owner_leaf_and_readable_by_owner(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = _upload(client, b"Echocardiogram report: EF 35%")
    assert r.status_code == 201, r.text
    body = r.json()
    rid = body["record_id"]
    assert body["lifecycle_state"] == "granted"
    assert body["search_terms_indexed"] == 2
    assert body["audit_share_deposited"] is True

    # The owner opens it through the owner leaf ...
    r = client.post(
        f"/subjects/{PATIENT}/read",
        json={"record_id": rid, "facility_id": "facility-a"},
    )
    assert r.status_code == 200, r.text
    assert (
        base64.b64decode(r.json()["plaintext_b64"]) == b"Echocardiogram report: EF 35%"
    )
    assert r.json()["content_type"] == "text/plain"
    # ... specialty alone is not a treating relationship for a new upload ...
    r = client.post(
        f"/subjects/{DOC_CARDIO}/read",
        json={"record_id": rid, "facility_id": "facility-a"},
    )
    assert r.status_code == 403, r.text
    assert "care-episode grant" in r.json()["detail"]
    # ... and an ER physician without consent is also refused.
    r = client.post(
        f"/subjects/{DOC_ER}/read", json={"record_id": rid, "facility_id": "facility-b"}
    )
    assert r.status_code == 403


def test_uploaded_record_can_be_opened_by_break_glass(federation):
    """The custodian kept share 1 and deposited share 3 for the new record."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = _upload(client, b"Uploaded by the patient")
    assert r.status_code == 201, r.text
    rid = r.json()["record_id"]
    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={
            "patient_id": PATIENT,
            "record_id": rid,
            "reason_code": "stroke",
            "justification": "Urgent stroke treatment needs medication history.",
        },
    )
    assert r.status_code == 200, r.text
    assert base64.b64decode(r.json()["plaintext_b64"]) == b"Uploaded by the patient"
    assert federation["repo"].get_lifecycle_state(rid) is LifecycleState.EMERGENCY_OPEN


def test_ingest_with_existing_record_id_leaves_shares_intact(federation):
    """Review F4: re-using a record_id is refused and the original still opens.

    Before the fix the custodian deposited new shares before the facility
    refused the duplicate, replacing the original record's shares for good.
    """
    client = _custodian(federation)
    _deposit_all(client, federation)
    first = _upload(client, b"Original report", record_id="rec-dup-001")
    assert first.status_code == 201, first.text

    again = _upload(client, b"Overwrite attempt", record_id="rec-dup-001")
    assert again.status_code == 409, again.text

    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={
            "patient_id": PATIENT,
            "record_id": "rec-dup-001",
            "reason_code": "stroke",
            "justification": "Urgent stroke treatment needs medication history.",
        },
    )
    assert r.status_code == 200, r.text
    assert base64.b64decode(r.json()["plaintext_b64"]) == b"Original report"


def test_failed_share_deposit_stores_no_record(federation):
    """Review F4: shares are deposited before ingest, so an audit outage leaves
    no record behind that break-glass could never open; a retry succeeds."""
    client = _custodian(federation, audit_deposit_ok=False)
    _deposit_all(client, federation)
    before = set(federation["repo"].records)

    r = _upload(client, b"Report during an audit outage")
    assert r.status_code == 503, r.text
    assert set(federation["repo"].records) == before  # nothing ingested

    # Setup was valid: the same upload works once the audit service is back.
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = _upload(client, b"Report during an audit outage")
    assert r.status_code == 201, r.text


def test_share_deposit_never_overwrites(federation):
    """Review F4: a second share for the same record is refused (409)."""
    client = _custodian(federation)
    body = {"x": 1, "share_hex": "00" * 33}
    assert client.post("/records/rec-x/shares", json=body).status_code == 201
    assert client.post("/records/rec-x/shares", json=body).status_code == 409


def test_upload_refused_without_owner_credential(federation):
    """Fail closed: never seal a record its owner could not open (ADR-0016)."""
    client = _custodian(federation)
    material = dict(federation["material"][PATIENT], credentials=[])
    client.post(f"/subjects/{PATIENT}/material", json=material)
    r = _upload(client, b"x")
    assert r.status_code == 403
    assert "owner credential" in r.json()["detail"]


def test_clinician_cannot_upload_as_a_patient(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{DOC_CARDIO}/records",
        json={
            "facility_id": "facility-a",
            "content_b64": base64.b64encode(b"x").decode(),
            "clinical_policy": CARDIO_POLICY,
        },
    )
    assert r.status_code == 403


def test_empty_or_malformed_upload_is_rejected_before_any_service_call(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    assert _upload(client, b"").status_code == 400
    r = client.post(
        f"/subjects/{PATIENT}/records",
        json={
            "facility_id": "facility-a",
            "content_b64": "%%%",
            "clinical_policy": CARDIO_POLICY,
        },
    )
    assert r.status_code == 400


def test_breakglass_refuses_a_release_entry_the_audit_service_did_not_sign(
    federation,
):
    """Review F31: a share whose release entry is not the audit service's
    signature over this flow is not presented to the facility."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    # Swap the key the custodian trusts: the stub's real signatures no longer
    # verify, exactly as if an impostor answered for the audit service.
    impostor_pub = generate_ec_keypair()[1]
    client.app.state.vault.audit_public_key_pem = public_key_to_pem(
        impostor_pub
    ).decode("ascii")

    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"},
    )
    assert r.status_code == 502
    assert "did not verify" in r.json()["detail"]
    assert "plaintext_b64" not in r.text
    assert federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED


def test_breakglass_refuses_an_audit_seq_that_goes_backwards(federation):
    """Review F31: a lower seq than one already seen means a truncated chain."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    client.app.state.vault.last_audit_seq = 10_000

    r = client.post(
        f"/subjects/{DOC_ER}/breakglass",
        json={"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"},
    )
    assert r.status_code == 502
    assert "truncated or replayed" in r.json()["detail"]


def test_concurrent_releases_finishing_out_of_order_are_accepted():
    """Review F31: two break-glasses requested together may see their release
    entries (seq 50 and 51) in either order; only a seq at or below what was
    seen before the request is refused."""
    vault = CustodianVault()
    before_a = vault.audit_seq_before_release()
    before_b = vault.audit_seq_before_release()
    vault.advance_audit_seq(51, before_b)
    vault.advance_audit_seq(50, before_a)  # answered later, committed earlier

    with pytest.raises(ValueError, match="truncated or replayed"):
        vault.advance_audit_seq(50, vault.audit_seq_before_release())


# --- Signed service calls (ADR-0066) ---------------------------------------------


def test_custodian_takes_only_signed_calls_from_allowed_kinds(federation):
    """Bootstrap-only deposits refuse a portal; an unsigned call is a 401."""
    client = _custodian(federation)
    material = federation["material"][DOC_CARDIO]
    # Positive control: bootstrap deposits.
    assert (
        client.post(f"/subjects/{DOC_CARDIO}/material", json=material).status_code
        == 201
    )
    portal = federation["services"].client(client.app, "custodian", caller="portal")
    refused = portal.post(f"/subjects/{DOC_ER}/material", json=material)
    assert refused.status_code == 403
    unsigned = TestClient(client.app).get(f"/subjects/{DOC_CARDIO}")
    assert unsigned.status_code == 401
    assert "public_key_pem" not in unsigned.text


# --- Share 1 replacement after a rotation (ADR-0069) ----------------------------


def _replace(client, generation: int, share_hex: str = "abcdef01"):
    return client.put(
        f"/records/{RECORD}/shares",
        json={"x": 1, "share_hex": share_hex, "generation": generation},
    )


def test_a_facility_replaces_share_1_during_the_records_expiry(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    facility = federation["services"].client(
        client.app, "custodian", caller="facility-a"
    )
    federation["repo"].upsert_lifecycle_state(RECORD, LifecycleState.EXPIRED)
    assert _replace(facility, 1).status_code == 200
    assert _replace(facility, 1).status_code == 200  # a retry is a no-op
    assert client.app.state.vault.get_share(RECORD) == (1, bytes.fromhex("abcdef01"))


def test_share_1_is_not_replaced_outside_the_records_expiry(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    facility = federation["services"].client(
        client.app, "custodian", caller="facility-a"
    )
    original = client.app.state.vault.get_share(RECORD)
    assert _replace(facility, 1).status_code == 409  # record is GRANTED
    federation["repo"].upsert_lifecycle_state(RECORD, LifecycleState.EXPIRED)
    assert _replace(client, 1).status_code == 403  # bootstrap is not a facility
    assert client.app.state.vault.get_share(RECORD) == original
    # A later generation may skip ahead (ADR-0073); the held one is final.
    assert _replace(facility, 2).status_code == 200
    assert _replace(facility, 2, share_hex="abcdef02").status_code == 409
    assert _replace(facility, 1, share_hex="abcdef02").status_code == 409
    assert client.app.state.vault.get_share(RECORD) == (1, bytes.fromhex("abcdef01"))


def test_share_1_replacement_needs_store_access(federation):
    """Without a view of the store it cannot tell an expiry rotation: refuse."""
    audit = _audit_stub({RECORD: federation["shares"]["share3"]})
    app = create_custodian_app(
        endpoints=CustodianEndpoints(audit=AUDIT),
        http_client=_router({**federation["apps"], "audit": audit}),
        identity=federation["services"].identity("custodian"),
        service_root=federation["root_cert"],
    )
    facility = federation["services"].client(app, "custodian", caller="facility-a")
    assert _replace(facility, 1).status_code == 503


def test_breakglass_after_rotation_uses_the_new_share_1(federation):
    """End to end through the custodian: expiry rotates, the custodian takes the
    new share 1, and the next break-glass opens with it (ADR-0069)."""
    client = _custodian(federation)
    _deposit_all(client, federation)
    body = {"patient_id": PATIENT, "record_id": RECORD, "reason_code": "stroke"}
    assert client.post(f"/subjects/{DOC_ER}/breakglass", json=body).status_code == 200

    federation["expiry_a"].expire_session(RECORD, force=True)
    deposit = federation["rotation"].deposits[-1]
    assert deposit["generation"] == 1
    # Hand the rotation's shares to the holders, as the facility's ports do.
    facility = federation["services"].client(
        client.app, "custodian", caller="facility-a"
    )
    federation["repo"].upsert_lifecycle_state(RECORD, LifecycleState.EXPIRED)
    x, share = deposit["clinician_share"]
    assert (
        facility.put(
            f"/records/{RECORD}/shares",
            json={"x": x, "share_hex": share.hex(), "generation": 1},
        ).status_code
        == 200
    )
    federation["repo"].upsert_lifecycle_state(RECORD, LifecycleState.GRANTED)
    client.app_audit_shares[RECORD] = deposit["audit_share"]  # type: ignore[attr-defined]

    again = client.post(f"/subjects/{DOC_ER}/breakglass", json=body)
    assert again.status_code == 200, again.text
    assert base64.b64decode(again.json()["plaintext_b64"]) == PLAINTEXT


# --- ADR-0072: a patient's revocation through the custodian -------------------

PHYSICIAN_ONLY = {
    "node_type": "leaf",
    "attribute": {"name": "role", "value": "physician"},
    "authority_id": "authority-med",
}


def test_patient_revokes_through_the_custodian_with_no_key_on_the_wire(federation):
    """Review F10/F13: the custodian signs the revocation with the patient's
    key and sends the signed event; no private key, DEK or attribute key goes
    to the facility, and the record is re-keyed and REVOKED."""
    seen: list[httpx.Request] = []
    client = _custodian(federation, seen=seen)
    _deposit_all(client, federation)
    seen.clear()

    r = client.post(
        f"/subjects/{PATIENT}/records/{RECORD}/revoke",
        json={"new_clinical_policy": PHYSICIAN_ONLY},
    )

    assert r.status_code == 200, r.text
    assert r.json()["lifecycle_state"] == "revoked"
    assert federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.REVOKED
    assert federation["rotation"].deposits[-1]["generation"] == 1
    (revoke,) = [q for q in seen if q.url.path.endswith("/revoke")]
    body = revoke.content.decode()
    assert "PRIVATE KEY" not in body
    for field in ("old_dek_b64", "actor_signing_key_pem", "attribute_keyring"):
        assert field not in body


def test_a_clinician_cannot_revoke_through_the_custodian(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{DOC_CARDIO}/records/{RECORD}/revoke",
        json={"new_clinical_policy": PHYSICIAN_ONLY},
    )
    assert r.status_code == 403
    assert federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED


def test_only_the_records_patient_revokes_it(federation):
    client = _custodian(federation)
    _deposit_all(client, federation)
    other = dict(federation["material"][PATIENT])
    other["credentials"] = []
    assert client.post("/subjects/pat-999/material", json=other).status_code == 201
    r = client.post(
        "/subjects/pat-999/records/rec-001/revoke",
        json={"new_clinical_policy": PHYSICIAN_ONLY},
    )
    assert r.status_code == 403
    assert federation["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED


def test_key_release_carries_the_subjects_possession_proof(federation):
    """ADR-0074: every key release the custodian asks for is signed by the
    credential's subject, and names that subject's certificate."""
    seen: list[httpx.Request] = []
    client = _custodian(federation, seen=seen)
    _deposit_all(client, federation)
    r = client.post(
        f"/subjects/{DOC_CARDIO}/read",
        json={"record_id": RECORD, "facility_id": "facility-a"},
    )
    assert r.status_code == 200, r.text
    releases = [q for q in seen if q.url.path == "/attribute-keys/release"]
    assert len(releases) == 2
    for request in releases:
        body = json.loads(request.content)
        assert body["possession"]["caller_id"] == DOC_CARDIO
        assert body["possession"]["operation"] == "attribute_key.release"
        assert body["subject_certificate_pem"].startswith("-----BEGIN CERTIFICATE")
