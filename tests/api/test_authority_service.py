"""Tests for the standalone Attribute Authority Service (P4-2, C6/C14).

No Postgres needed -- ``AttributeAuthority`` is a pure in-memory object
(ARCHITECTURE.md §7 / ADR-0039: the whole federation is re-bootstrapped fresh
every run, so this service holds no durable state of its own).
"""

from __future__ import annotations

import pytest
from api.authority_service import create_authority_app
from fastapi.testclient import TestClient
from identity.root_anchor import generate_root_anchor

from tests.service_pki import PersonPKI, ServicePKI, release_body


@pytest.fixture()
def services() -> ServicePKI:
    return ServicePKI(generate_root_anchor())


@pytest.fixture()
def people(services) -> PersonPKI:
    return PersonPKI(services.root)


@pytest.fixture()
def alice(people):
    return people.clinician("dr-alice")


@pytest.fixture()
def app(services, people):
    return create_authority_app(
        "authority-med",
        frozenset({"role"}),
        service_root=services.root.certificate,
        subject_trust=people.trust,
    )


@pytest.fixture()
def client(app, services) -> TestClient:
    """Signed as bootstrap, which issues credentials and registers certificates."""
    return services.client(app, "authority-med")


@pytest.mark.parametrize("caller", ["custodian", "facility-a", "bootstrap"])
def test_policy_sealing_services_get_authoring_keys(app, services, caller) -> None:
    """ADR-0066: authoring keys go to the services that seal policies -- the
    custodian and bootstrap at ingest, a facility at its expiry rotation."""
    body = {"name": "role", "value": "physician"}
    signed = services.client(app, "authority-med", caller=caller)
    assert signed.post("/attribute-keys/author", json=body).status_code == 200


def test_author_endpoint_refuses_unauthenticated_caller(app, services) -> None:
    """Review F14: no authoring key without a signed request from a sealing
    service (ADR-0066 replaces the interim address allowlist).

    The authoring key is the very key /attribute-keys/release gates behind a
    credential, so an open authoring endpoint bypassed the credential check.
    """
    body = {"name": "role", "value": "physician"}
    # Positive control: the same request, signed by the custodian, succeeds.
    custodian = services.client(app, "authority-med", caller="custodian")
    assert custodian.post("/attribute-keys/author", json=body).status_code == 200

    unsigned = TestClient(app).post("/attribute-keys/author", json=body)
    assert unsigned.status_code == 401
    assert "key_b64" not in unsigned.text

    portal = services.client(app, "authority-med", caller="portal")
    refused = portal.post("/attribute-keys/author", json=body)
    assert refused.status_code == 403
    assert "key_b64" not in refused.text


def test_a_service_from_another_root_is_refused(app) -> None:
    """A certificate the federation root did not issue authenticates nothing."""
    rogue = ServicePKI(generate_root_anchor())
    response = rogue.client(app, "authority-med", caller="custodian").post(
        "/attribute-keys/author", json={"name": "role", "value": "physician"}
    )
    assert response.status_code == 401
    assert "key_b64" not in response.text


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


def test_issue_verify_and_release_attribute_key(client: TestClient, alice) -> None:
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

    release = client.post(
        "/attribute-keys/release", json=release_body(credential, alice)
    )
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


@pytest.mark.claim("C10", level="system")
def test_revoked_credential_fails_verification_and_key_release(
    client: TestClient, alice
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

    release = client.post("/attribute-keys/release", json=release_body(issued, alice))
    assert release.status_code == 403


@pytest.mark.claim("C10", level="system")
def test_expired_credential_release_fails_closed(client: TestClient, alice) -> None:
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

    release = client.post("/attribute-keys/release", json=release_body(issued, alice))
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


# --- ADR-0074 / review F15: proof of possession ---------------------------


def _issue(client: TestClient, subject_id: str = "dr-alice") -> dict:
    return client.post(
        "/credentials/issue",
        json={
            "subject_id": subject_id,
            "attribute": {"name": "role", "value": "physician"},
        },
    ).json()["credential"]


@pytest.mark.claim("C10", level="system")
def test_copied_credential_without_subject_signature_gets_no_key(
    client: TestClient, people, alice
) -> None:
    """Review F15: a credential is public signed data. Someone holding a copy
    -- here another certified clinician, signing with their own key -- gets
    nothing; the credential's subject asking does (positive control)."""
    credential = _issue(client)
    mallory = people.clinician("dr-mallory")

    copied = client.post(
        "/attribute-keys/release", json=release_body(credential, mallory)
    )
    assert copied.status_code == 403
    assert "key_b64" not in copied.text

    # Mallory's envelope under Alice's certificate does not verify either.
    forged = release_body(credential, mallory)
    forged["subject_certificate_pem"] = alice.certificate_pem
    forged["possession"]["caller_id"] = "dr-alice"
    refused = client.post("/attribute-keys/release", json=forged)
    assert refused.status_code == 403
    assert "key_b64" not in refused.text

    owner = client.post("/attribute-keys/release", json=release_body(credential, alice))
    assert owner.status_code == 200


def test_bare_credential_is_refused(client: TestClient) -> None:
    """The old request shape -- the credential alone -- is not accepted."""
    response = client.post(
        "/attribute-keys/release", json={"credential": _issue(client)}
    )
    assert response.status_code == 422
    assert "key_b64" not in response.text


def test_possession_for_another_credential_is_refused(
    client: TestClient, alice
) -> None:
    """The subject's signature binds one credential: it does not release another."""
    first, second = _issue(client), _issue(client)
    body = release_body(first, alice)
    body["credential"] = second
    response = client.post("/attribute-keys/release", json=body)
    assert response.status_code == 403
    assert "PossessionError" in response.json()["detail"]


def test_replayed_release_envelope_rejected(client: TestClient, alice) -> None:
    """A captured release request is one-time: replaying it releases nothing."""
    body = release_body(_issue(client), alice)
    assert client.post("/attribute-keys/release", json=body).status_code == 200
    replay = client.post("/attribute-keys/release", json=body)
    assert replay.status_code == 403
    assert "ReplayedRequestError" in replay.json()["detail"]


def test_subject_certificate_from_unknown_ca_is_refused(
    client: TestClient, services
) -> None:
    """A certificate from a CA the authority is not configured with is no proof."""
    from tests.service_pki import PersonPKI

    rogue = PersonPKI(generate_root_anchor()).clinician("dr-alice")
    response = client.post(
        "/attribute-keys/release", json=release_body(_issue(client), rogue)
    )
    assert response.status_code == 403
    assert "ChainValidationError" in response.json()["detail"]


def test_no_subject_trust_releases_nothing(services, alice) -> None:
    """Without configured facility CAs the authority cannot check possession."""
    app = create_authority_app(
        "authority-med", frozenset({"role"}), service_root=services.root.certificate
    )
    client = services.client(app, "authority-med")
    credential = client.post(
        "/credentials/issue",
        json={
            "subject_id": "dr-alice",
            "attribute": {"name": "role", "value": "physician"},
        },
    ).json()["credential"]
    response = client.post(
        "/attribute-keys/release", json=release_body(credential, alice)
    )
    assert response.status_code == 503
