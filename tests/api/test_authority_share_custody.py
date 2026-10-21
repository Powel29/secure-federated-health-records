"""The home authority's custody of share 2 (ADR-0089).

As a patient's home authority, an attribute authority holds share 2 of the
weighted 3-of-4 break-glass split and releases it only against an emergency
assertion it has validated itself -- the same check the audit service runs
(``api.share_release``) -- sealed to a root-certified facility gate. These are
the negative tests for that control; each refusal is checked against a
positive control in the same fixture, and no refusal leaves a share behind.
"""

from __future__ import annotations

import secrets

import pytest
from api.authority_service import create_authority_app
from api.repository import InMemoryStorageRepository
from breakglass import create_emergency_assertion
from breakglass.assertion import clinical_context_digest
from breakglass.share_sealing import SealedShare, open_sealed_share
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import certificate_to_pem, generate_ec_keypair
from fastapi.testclient import TestClient
from identity.certificates import (
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)

from tests.api.conftest import make_trust
from tests.sealing import facility_statement, seal_for

AUTHORITY = "authority-net"
RECORD = "rec-home-1"
JUSTIFICATION = "Unresponsive on arrival; allergy history needed now."
SHARE2 = (2, secrets.token_bytes(33))


def _app(pki, **overrides):
    repo = overrides.pop("repo", None) or InMemoryStorageRepository()
    kwargs = dict(
        service_root=pki["root"].certificate,
        identity=pki["services"].identity(AUTHORITY),
        trust=make_trust(pki),
        state_loader=repo.get_lifecycle_state,
    )
    kwargs.update(overrides)
    return create_authority_app(
        AUTHORITY, frozenset({"specialty", "facility", "owner"}), **kwargs
    )


@pytest.fixture()
def custody(federation_pki):
    pki = federation_pki
    repo = InMemoryStorageRepository()
    app = _app(pki, repo=repo)
    services = pki["services"]
    custodian = services.client(app, AUTHORITY, caller="custodian")
    gate_key, gate_statement = facility_statement(services)
    return {
        "pki": pki,
        "repo": repo,
        "app": app,
        "custodian": custodian,
        "facility": services.client(app, AUTHORITY, caller="facility-a"),
        "gate_key": gate_key,
        "gate_statement": gate_statement,
    }


def _deposit(client, *shares, record_id=RECORD):
    """Deposit ``shares`` (default: share 2 alone), each sealed to the app."""
    shares = shares or (SHARE2,)
    return client.post(
        "/breakglass/shares",
        json={
            "share_key": record_id,
            "sealed_shares": [seal_for(client, record_id, s) for s in shares],
        },
    )


def _request(c, *, record_id=RECORD, signing_key=None, cert=None, **overrides):
    pki = c["pki"]
    assertion = create_emergency_assertion(
        patient_id="patient-001",
        clinician_id="dr-alice",
        facility_id="facility-a",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        signing_key=signing_key or pki["alice_priv"],
        clinical_context_digest=clinical_context_digest(record_id, JUSTIFICATION, ""),
    )
    body = {
        "share_key": RECORD,
        "assertion": assertion.model_dump(mode="json"),
        "clinician_certificate_pem": certificate_to_pem(
            cert or pki["alice_cert"]
        ).decode("ascii"),
        "justification": JUSTIFICATION,
        "recipient": c["gate_statement"],
    }
    body.update(overrides)
    return body


def _opened(c, response) -> list[tuple[int, bytes]]:
    return [
        open_sealed_share(
            SealedShare.model_validate(sealed),
            record_id=RECORD,
            service_id="facility-a",
            key=c["gate_key"],
        )
        for sealed in response.json()["sealed_shares"]
    ]


def _released_nothing(response) -> None:
    assert response.status_code >= 400
    assert "sealed_shares" not in response.text
    assert SHARE2[1].hex() not in response.text


# --- Positive control -----------------------------------------------------------


def test_positive_control_valid_assertion_releases_share_2_to_the_gate(custody):
    assert _deposit(custody["custodian"]).status_code == 201
    r = custody["custodian"].post("/breakglass/release", json=_request(custody))
    assert r.status_code == 200, r.text
    # Sealed to facility-a's gate: only the gate opens it, the caller cannot.
    assert _opened(custody, r) == [SHARE2]
    assert SHARE2[1].hex() not in r.text


def test_the_share_key_is_published_as_an_authority(custody):
    statement = TestClient(custody["app"]).get("/share-key").json()
    assert (statement["service_id"], statement["kind"]) == (AUTHORITY, "authority")


# --- Holds exactly share 2 ------------------------------------------------------


@pytest.mark.parametrize(
    "shares",
    [
        [(1, b"\x01" * 33)],
        [(3, b"\x03" * 33)],
        [(4, b"\x04" * 33)],
        [SHARE2, (3, b"\x03" * 33)],
        [SHARE2, SHARE2],
    ],
    ids=["clinician-share", "audit-3", "audit-4", "2-plus-3", "duplicate"],
)
def test_deposit_of_anything_but_share_2_is_refused(custody, shares):
    """ADR-0089: a misrouted share must not give custodian + home authority
    three points, so this holder takes share 2 and nothing else."""
    r = _deposit(custody["custodian"], *shares)
    assert r.status_code == 400, r.text
    assert not custody["app"].state.shares.has(RECORD)
    # Positive control in the same fixture: share 2 alone is accepted.
    assert _deposit(custody["custodian"]).status_code == 201


def test_a_held_share_is_never_overwritten(custody):
    assert _deposit(custody["custodian"]).status_code == 201
    other = (2, secrets.token_bytes(33))
    assert _deposit(custody["custodian"], other).status_code == 409
    assert custody["app"].state.shares.get(RECORD) == (SHARE2,)


# --- Release needs a valid assertion --------------------------------------------


class TestReleaseNeedsAValidAssertion:
    """Share 2 moves only against an assertion validated here (ADR-0089). It is
    one point of three, so this is defence in depth behind the audit service,
    but a holder that releases on a caller's say-so is a finding."""

    @pytest.fixture(autouse=True)
    def _held(self, custody):
        assert _deposit(custody["custodian"]).status_code == 201

    def test_no_assertion_releases_nothing(self, custody):
        body = _request(custody)
        for field in ("assertion", "clinician_certificate_pem"):
            r = custody["custodian"].post(
                "/breakglass/release",
                json={k: v for k, v in body.items() if k != field},
            )
            assert r.status_code == 422
            _released_nothing(r)
        assert (
            custody["custodian"].post("/breakglass/release", json=body).status_code
            == 200
        )

    @pytest.mark.claim("C3", level="system")
    def test_assertion_for_another_record_releases_nothing(self, custody):
        r = custody["custodian"].post(
            "/breakglass/release", json=_request(custody, record_id="rec-other")
        )
        assert r.status_code == 403, r.text
        _released_nothing(r)

    @pytest.mark.claim("C3", level="system")
    def test_assertion_not_signed_by_the_certificate_key_releases_nothing(
        self, custody
    ):
        forger, _ = generate_ec_keypair()
        r = custody["custodian"].post(
            "/breakglass/release", json=_request(custody, signing_key=forger)
        )
        assert r.status_code == 400, r.text
        assert "InvalidSignatureError" in r.text
        _released_nothing(r)

    def test_clinician_from_an_untrusted_ca_releases_nothing(self, custody):
        from identity.root_anchor import generate_root_anchor

        rogue_root = generate_root_anchor()
        ca_priv, ca_pub = generate_ec_keypair()
        ca_cert = issue_facility_ca_certificate(rogue_root, "facility-a", ca_pub)
        doc_priv, doc_pub = generate_ec_keypair()
        doc_cert = issue_clinician_certificate(ca_priv, ca_cert, "dr-alice", doc_pub)
        r = custody["custodian"].post(
            "/breakglass/release",
            json=_request(custody, signing_key=doc_priv, cert=doc_cert),
        )
        assert r.status_code == 403, r.text
        _released_nothing(r)

    @pytest.mark.claim("C8", level="system")
    def test_a_replayed_assertion_releases_nothing(self, custody):
        body = _request(custody)
        assert (
            custody["custodian"].post("/breakglass/release", json=body).status_code
            == 200
        )
        again = custody["custodian"].post("/breakglass/release", json=body)
        assert again.status_code == 400, again.text
        assert "ReplayedAssertionError" in again.text
        _released_nothing(again)

    def test_a_recipient_that_is_not_a_facility_gets_nothing(self, custody):
        from tests.sealing import statement_of

        not_a_gate = statement_of(custody["app"])  # this authority's own key
        r = custody["custodian"].post(
            "/breakglass/release", json=_request(custody, recipient=not_a_gate)
        )
        assert r.status_code == 403, r.text
        _released_nothing(r)

    def test_only_the_custodian_or_bootstrap_may_ask(self, custody):
        portal = custody["pki"]["services"].client(
            custody["app"], AUTHORITY, caller="portal"
        )
        r = portal.post("/breakglass/release", json=_request(custody))
        assert r.status_code == 403
        _released_nothing(r)
        unsigned = TestClient(custody["app"]).post(
            "/breakglass/release", json=_request(custody)
        )
        assert unsigned.status_code == 401
        _released_nothing(unsigned)


def test_without_trust_anchors_nothing_is_released(federation_pki):
    app = _app(federation_pki, trust=None)
    services = federation_pki["services"]
    custodian = services.client(app, AUTHORITY, caller="custodian")
    gate_key, statement = facility_statement(services)
    assert _deposit(custodian).status_code == 201
    body = _request(
        {"pki": federation_pki, "gate_statement": statement}, record_id=RECORD
    )
    r = custodian.post("/breakglass/release", json=body)
    assert r.status_code == 503
    _released_nothing(r)


def test_without_a_service_identity_the_authority_holds_no_share(federation_pki):
    app = _app(federation_pki, identity=None)
    custodian = federation_pki["services"].client(app, AUTHORITY, caller="custodian")
    # No share key is published: the route does not exist, so an unsigned
    # call to it is refused like any other non-public path.
    published = TestClient(app).get("/share-key")
    assert published.status_code in (401, 404)
    assert "public_key" not in published.text
    r = _deposit(custodian)
    assert r.status_code == 503
    assert not app.state.shares.has(RECORD)


# --- Replacement only by a rotation ---------------------------------------------


def _replace(client, generation, share=(2, b"\xab" * 33)):
    return client.put(
        f"/breakglass/shares/{RECORD}",
        json={
            "sealed_shares": [seal_for(client, RECORD, share)],
            "generation": generation,
        },
    )


def test_a_facility_replaces_share_2_during_the_records_rotation(custody):
    assert _deposit(custody["custodian"]).status_code == 201
    custody["repo"].upsert_lifecycle_state(
        record_id=RECORD, state=LifecycleState.EXPIRED
    )
    assert _replace(custody["facility"], 1).status_code == 200
    assert _replace(custody["facility"], 1).status_code == 200  # a retry is a no-op
    assert custody["app"].state.shares.get(RECORD) == ((2, b"\xab" * 33),)


def test_share_2_is_replaced_only_by_a_facility_during_a_rotation(custody):
    assert _deposit(custody["custodian"]).status_code == 201
    assert _replace(custody["facility"], 1).status_code == 409  # never ingested state
    custody["repo"].upsert_lifecycle_state(
        record_id=RECORD, state=LifecycleState.GRANTED
    )
    assert _replace(custody["facility"], 1).status_code == 409  # not rotating
    custody["repo"].upsert_lifecycle_state(
        record_id=RECORD, state=LifecycleState.REVOKED
    )
    assert _replace(custody["custodian"], 1).status_code == 403  # not a facility
    assert custody["app"].state.shares.get(RECORD) == (SHARE2,)
    # A later generation may skip ahead (ADR-0081); none is rolled back.
    assert _replace(custody["facility"], 2).status_code == 200
    assert _replace(custody["facility"], 1, (2, b"\xcd" * 33)).status_code == 409
    assert _replace(custody["facility"], 3, (3, b"\xcd" * 33)).status_code == 400
    assert custody["app"].state.shares.get(RECORD) == ((2, b"\xab" * 33),)


def test_share_2_replacement_needs_store_access(federation_pki):
    app = _app(federation_pki, state_loader=None)
    services = federation_pki["services"]
    assert (
        _deposit(services.client(app, AUTHORITY, caller="custodian")).status_code == 201
    )
    facility = services.client(app, AUTHORITY, caller="facility-a")
    assert _replace(facility, 1).status_code == 503
