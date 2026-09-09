"""Tests for the standalone Attribute Authority Service (P4-2, C6/C14).

No Postgres needed -- ``AttributeAuthority`` is a pure in-memory object
(ARCHITECTURE.md §7 / ADR-0039: the whole federation is re-bootstrapped fresh
every run, so this service holds no durable state of its own).
"""

from __future__ import annotations

import pytest
from api.authority_service import create_authority_app
from fastapi.testclient import TestClient


@pytest.fixture()
def client() -> TestClient:
    app = create_authority_app("authority-med", frozenset({"role"}))
    return TestClient(app)


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "authority_id": "authority-med"}


def test_public_key_is_pem(client: TestClient) -> None:
    r = client.get("/public-key")
    assert r.status_code == 200
    assert "BEGIN PUBLIC KEY" in r.json()["public_key_pem"]


def test_certificate_round_trip(client: TestClient) -> None:
    assert client.get("/certificate").json() == {"certificate_pem": None}

    r = client.put("/certificate", json={"certificate_pem": "-----FAKE-----"})
    assert r.status_code == 200
    assert r.json() == {"certificate_pem": "-----FAKE-----"}

    assert client.get("/certificate").json() == {"certificate_pem": "-----FAKE-----"}


def test_issue_verify_and_release_attribute_key(client: TestClient) -> None:
    r = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
        },
    )
    assert r.status_code == 201
    credential = r.json()["credential"]
    assert credential["issuer_id"] == "authority-med"
    assert credential["status"] == "active"

    verify = client.post("/credentials/verify", json={"credential": credential})
    assert verify.status_code == 200
    assert verify.json() == {"valid": True}

    status_resp = client.post("/credentials/status", json={"credential": credential})
    assert status_resp.status_code == 200
    assert status_resp.json() == {"status": "active"}

    release = client.post("/attribute-keys/release", json={"credential": credential})
    assert release.status_code == 200
    released = release.json()
    assert released["name"] == "role"
    assert released["value"] == "physician"

    authored = client.post(
        "/attribute-keys/author", json={"name": "role", "value": "physician"}
    )
    assert authored.status_code == 200
    # One key per attribute (ADR-0026): authoring and holder-release paths
    # must agree, or a policy leaf sealed at ingest could never be opened.
    assert authored.json()["key_b64"] == released["key_b64"]


def test_owner_credential_binds_attribute_to_patient(client: TestClient) -> None:
    r = client.post(
        "/credentials/issue",
        json={
            "subject_id": "patient-001",
            "attribute": {"name": "ignored", "value": "ignored"},
            "owner": True,
        },
    )
    assert r.status_code == 403  # authority-med does not own "owner" namespace


def test_issuing_outside_owned_namespace_is_rejected(client: TestClient) -> None:
    r = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-bob",
            "attribute": {"name": "specialty", "value": "cardiology"},
        },
    )
    assert r.status_code == 403


def test_revoked_credential_fails_verification_and_key_release(
    client: TestClient,
) -> None:
    issued = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
        },
    ).json()["credential"]

    revoke = client.post(
        f"/credentials/{issued['serial']}/revoke", params={"reason": "left staff"}
    )
    assert revoke.status_code == 200
    assert revoke.json()["reason"] == "left staff"

    verify = client.post("/credentials/verify", json={"credential": issued})
    assert verify.status_code == 403
    assert "CredentialRevokedError" in verify.json()["detail"]

    release = client.post("/attribute-keys/release", json={"credential": issued})
    assert release.status_code == 403


def test_expired_credential_release_fails_closed(client: TestClient) -> None:
    import datetime

    now = datetime.datetime.now(datetime.timezone.utc)
    issued = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
            "valid_from": (now - datetime.timedelta(days=2)).isoformat(),
            "valid_until": (now - datetime.timedelta(days=1)).isoformat(),
        },
    ).json()["credential"]

    release = client.post("/attribute-keys/release", json={"credential": issued})
    assert release.status_code == 403
    assert "CredentialExpiredError" in release.json()["detail"]


def test_forged_signature_is_rejected(client: TestClient) -> None:
    issued = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
        },
    ).json()["credential"]

    tampered = dict(issued)
    tampered["subject_id"] = "dr-mallory"

    verify = client.post("/credentials/verify", json={"credential": tampered})
    assert verify.status_code == 403
    assert "InvalidSignatureError" in verify.json()["detail"]
