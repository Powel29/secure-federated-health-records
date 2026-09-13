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
from api.authority_service import create_authority_app
from api.custodian_service import (
    CustodianEndpoints,
    create_custodian_app,
)
from api.hospital import create_hospital_app
from api.repository import InMemoryStorageRepository
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import (
    certificate_to_pem,
    generate_ec_keypair,
    private_key_to_pem,
)
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import generate_root_anchor
from lifecycle.expiry import EmergencyExpiryManager
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.ingest import ingest_record

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
    shares: dict[str, tuple[int, bytes]], *, commit_ok: bool = True
) -> FastAPI:
    """Stand-in for ``api.audit_service`` without Postgres.

    Honours the one property the custodian relies on: the share is released
    only when the commit succeeded (``commit_ok``), otherwise 503 and nothing.
    """
    app = FastAPI()
    state: dict[str, Any] = {"seq": 0, "entries": []}

    @app.post("/entries")
    def entries(payload: dict[str, Any]) -> dict[str, Any]:
        state["seq"] += 1
        entry = {"seq": state["seq"], **payload}
        state["entries"].append(entry)
        return {"entry": entry}

    @app.post("/breakglass/release")
    def release(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["share_key"] not in shares:
            raise HTTPException(status_code=404, detail="no share held")
        if not commit_ok:
            raise HTTPException(
                status_code=503, detail="log commit failed; share was not released"
            )
        state["seq"] += 1
        entry = {"seq": state["seq"], **payload}
        state["entries"].append(entry)
        x, share = shares[payload["share_key"]]
        return {"x": x, "share_hex": share.hex(), "entry": entry}

    app.state.log = state
    return app


def _router(apps: dict[str, FastAPI]) -> httpx.Client:
    """An httpx client whose transport dispatches by hostname to in-process apps."""
    clients = {host: TestClient(app) for host, app in apps.items()}

    def handler(request: httpx.Request) -> httpx.Response:
        host = urlparse(str(request.url)).hostname or ""
        client = clients[host]
        resp = client.request(
            request.method,
            request.url.path,
            content=request.content,
            headers={"content-type": "application/json"},
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

    app_med = create_authority_app("authority-med", frozenset({"role"}))
    app_net = create_authority_app(
        "authority-net", frozenset({"specialty", "facility", "owner"})
    )
    med = TestClient(app_med)
    net = TestClient(app_net)

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
    )
    repo = InMemoryStorageRepository()
    repo.insert_record(ingest.record)
    repo.insert_dek_wrapping(ingest.dek_wrapping)
    assert ingest.emergency_dek_wrapping is not None
    repo.insert_dek_wrapping(ingest.emergency_dek_wrapping)
    repo.store_compiled_policy(ingest.record.policy_id, ingest.compiled_policy)
    repo.upsert_lifecycle_state(record_id=RECORD, state=LifecycleState.GRANTED)

    life_priv, _ = generate_ec_keypair()
    expiry = EmergencyExpiryManager(signing_key=life_priv, default_duration_seconds=60)
    app_fa = create_hospital_app("facility-a", repository=repo)
    app_fb = create_hospital_app("facility-b", repository=repo, expiry_manager=expiry)

    # Clinician identities: certs from their facility CA, PRE keypairs.
    cardio_priv, cardio_pub = generate_ec_keypair()
    cardio_cert = issue_clinician_certificate(fa_priv, fa_cert, DOC_CARDIO, cardio_pub)
    er_priv, er_pub = generate_ec_keypair()
    er_cert = issue_clinician_certificate(fb_priv, fb_cert, DOC_ER, er_pub)
    er_pre_priv, er_pre_pub = generate_pre_keypair()
    pat_priv, _ = generate_ec_keypair()

    return {
        "apps": {
            "authority-med": app_med,
            "authority-net": app_net,
            "facility-a": app_fa,
            "facility-b": app_fb,
        },
        "repo": repo,
        "record": ingest.record,
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
                "credentials": creds[PATIENT],
            },
        },
    }


def _custodian(
    federation: dict[str, Any], *, audit_commit_ok: bool = True
) -> TestClient:
    audit = _audit_stub(
        {RECORD: federation["shares"]["share3"]}, commit_ok=audit_commit_ok
    )
    http = _router({**federation["apps"], "audit": audit})
    app = create_custodian_app(
        endpoints=CustodianEndpoints(
            authorities={"authority-med": AUTH_MED, "authority-net": AUTH_NET},
            facilities={"facility-a": FACILITY_A, "facility-b": FACILITY_B},
            audit=AUDIT,
        ),
        http_client=http,
        record_loader=federation["repo"].get_record,
        root_certificate_pem=federation["root_pem"],
        facility_ca_certificate_pems={
            "facility-a": federation["fa_pem"],
            "facility-b": federation["fb_pem"],
        },
    )
    client = TestClient(app)
    client.app_audit = audit  # type: ignore[attr-defined]
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
    pub = r.json()["patient_public_key_pem"]
    assert grant["status"] == "granted"

    # The facility verifies the patient signature and stores the grant.
    fa = TestClient(federation["apps"]["facility-a"])
    r = fa.post("/consent/grants", json={"grant": grant, "patient_public_key_pem": pub})
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
    assert body["facility_id"] == "facility-b"
    assert body["transition_event"]["to_state"] == "emergency_open"
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
