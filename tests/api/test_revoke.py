"""Tests for the facility's revocation endpoint (P3-7, P3-12, ADR-0080).

A patient revokes by signing ``GRANTED -> REVOKED`` with their own key (in the
custodian) and presenting their certificate. The facility recovers the old DEK
itself and re-keys the record with the expiry rotation (ADR-0069), so no
private key or DEK is sent (review F10/F13). Each refusal below is checked to
leave the record exactly as it was.
"""

from __future__ import annotations

import datetime

import httpx
import pytest
from api import schemas
from breakglass.emergency_key import THRESHOLD
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import certificate_to_pem, generate_ec_keypair
from identity.certificates import issue_patient_certificate
from lifecycle.state_machine import create_transition_event
from policy.engine import decrypt_record_via_policy, unwrap_dek_via_policy
from pydantic import BaseModel
from records.exceptions import DecryptionError, UnwrappingError
from records.service import decrypt_record, unwrap_dek
from shamir import combine_shares

from tests.shares import deposited_unlock_points, unlock_points

RECORD = "rec-001"
PATIENT = "patient-001"

PHYSICIAN_ONLY = PolicyTree(
    node_type=PolicyNodeType.LEAF,
    attribute=Attribute(name="role", value="physician"),
    authority_id="authority-med",
)


def _event(signing_key, *, actor_id=PATIENT, from_state=LifecycleState.GRANTED):
    return create_transition_event(
        record_id=RECORD,
        from_state=from_state,
        to_state=LifecycleState.REVOKED,
        actor_id=actor_id,
        signing_key=signing_key,
    )


def _body(event, certificate_pem, policy=PHYSICIAN_ONLY):
    return {
        "transition_event": event.model_dump(mode="json"),
        "actor_certificate_pem": certificate_pem,
        "new_clinical_policy": policy.model_dump(mode="json"),
        "correlation_id": "corr-rev-001",
    }


def _patient_body(setup):
    pki = setup["pki"]
    return _body(_event(pki["pat_priv"]), pki["pat_cert_pem"])


def _assert_untouched(setup, original):
    repo = setup["repo"]
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.GRANTED
    assert repo.get_record(RECORD) == original
    assert setup["rotation"].deposits == []


def test_patient_revokes_by_signed_transition(test_setup):
    """The patient's signed revocation re-keys the record and moves it to
    REVOKED; the old DEK opens nothing and the owner still reads it."""
    repo, attrs = test_setup["repo"], test_setup["attrs"]
    old_record = repo.get_record(RECORD)
    old_dek = unwrap_dek_via_policy(
        repo.get_compiled_policy(old_record.policy_id),
        attrs["attr_keyring"],
        test_setup["wrapping"],
    )

    response = test_setup["client"].post(
        f"/records/{RECORD}/revoke", json=_patient_body(test_setup)
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["new_generation"] == test_setup["wrapping"].generation + 1
    assert data["transition_event"]["to_state"] == LifecycleState.REVOKED.value
    assert data["breakglass_provisioned"] is True
    assert repo.get_lifecycle_state(RECORD) is LifecycleState.REVOKED

    rotated = repo.get_record(RECORD)
    assert rotated.policy_id == data["new_policy_id"] != old_record.policy_id
    with pytest.raises(DecryptionError):
        decrypt_record(rotated, old_dek)
    owner_leaf = ("authority-net", "owner", PATIENT)
    plaintext = decrypt_record_via_policy(
        repo.get_compiled_policy(rotated.policy_id),
        {owner_leaf: attrs["attr_keyring"][owner_leaf]},
        repo.get_wrapping_for_record(RECORD, wrapped_for=rotated.policy_id),
        rotated,
    )
    assert plaintext == test_setup["plaintext"]
    # Logged before it was stored (review F10).
    assert test_setup["audit_sink"].of_type("record.revoked")


def test_break_glass_on_the_revoked_record_uses_the_new_shares(test_setup):
    """Review F10 item 5: the emergency path is re-keyed with the DEK, so the
    holders' new shares open the rotated record and the old ones do not."""
    response = test_setup["client"].post(
        f"/records/{RECORD}/revoke", json=_patient_body(test_setup)
    )
    assert response.status_code == 200, response.text
    repo = test_setup["repo"]
    (deposit,) = test_setup["rotation"].deposits
    new_key = combine_shares(deposited_unlock_points(deposit), k=THRESHOLD)
    emergency = repo.get_wrapping_for_record(RECORD, wrapped_for="emergency")
    assert emergency.generation == deposit["generation"]
    rotated = repo.get_record(RECORD)
    assert decrypt_record(rotated, unwrap_dek(emergency, new_key)) == (
        test_setup["plaintext"]
    )
    old_key = combine_shares(unlock_points(test_setup["em_shares"]), k=THRESHOLD)
    with pytest.raises(UnwrappingError):
        unwrap_dek(emergency, old_key)


def test_request_carrying_a_private_key_or_dek_is_refused(test_setup):
    """Review F10/F13: the old fields are rejected, not silently ignored."""
    original = test_setup["repo"].get_record(RECORD)
    for extra in (
        {"actor_signing_key_pem": "-----BEGIN PRIVATE KEY-----"},
        {"old_dek_b64": "AAAA"},
        {"attribute_keyring": {}},
    ):
        body = {**_patient_body(test_setup), **extra}
        response = test_setup["client"].post(f"/records/{RECORD}/revoke", json=body)
        assert response.status_code == 422
    _assert_untouched(test_setup, original)


def test_clinician_cannot_revoke(test_setup):
    """P3-12: a clinician's own signed event and certificate revoke nothing."""
    pki = test_setup["pki"]
    original = test_setup["repo"].get_record(RECORD)
    body = _body(
        _event(pki["alice_priv"], actor_id="dr-alice"),
        certificate_to_pem(pki["alice_cert"]).decode("ascii"),
    )
    response = test_setup["client"].post(f"/records/{RECORD}/revoke", json=body)
    assert response.status_code == 403
    _assert_untouched(test_setup, original)
    assert test_setup["audit_sink"].of_type("access_denied")


def test_another_patient_cannot_revoke(test_setup):
    """A certified patient revokes their own records only."""
    pki = test_setup["pki"]
    other_key, other_pub = generate_ec_keypair()
    other_cert = issue_patient_certificate(
        pki["fa_priv"], pki["fa_cert"], "patient-002", other_pub
    )
    original = test_setup["repo"].get_record(RECORD)
    body = _body(
        _event(other_key, actor_id="patient-002"),
        certificate_to_pem(other_cert).decode("ascii"),
    )
    response = test_setup["client"].post(f"/records/{RECORD}/revoke", json=body)
    assert response.status_code == 403
    _assert_untouched(test_setup, original)


def test_event_not_signed_by_the_patient_is_refused(test_setup):
    """The patient's certificate with someone else's signature is a forgery."""
    pki = test_setup["pki"]
    original = test_setup["repo"].get_record(RECORD)
    body = _body(_event(pki["alice_priv"]), pki["pat_cert_pem"])
    response = test_setup["client"].post(f"/records/{RECORD}/revoke", json=body)
    assert response.status_code == 403
    assert "InvalidSignatureError" in response.json()["detail"]
    _assert_untouched(test_setup, original)


def test_stale_revocation_event_is_refused(test_setup):
    """A revocation signed long ago cannot be held back and replayed later."""
    pki = test_setup["pki"]
    original = test_setup["repo"].get_record(RECORD)
    old = create_transition_event(
        record_id=RECORD,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=PATIENT,
        signing_key=pki["pat_priv"],
        issued_at=datetime.datetime.now(datetime.timezone.utc)
        - datetime.timedelta(days=1),
    )
    response = test_setup["client"].post(
        f"/records/{RECORD}/revoke", json=_body(old, pki["pat_cert_pem"])
    )
    assert response.status_code == 400
    _assert_untouched(test_setup, original)


def test_replayed_revocation_event_is_refused(test_setup, monkeypatch):
    """The event id is one-time: after a revocation that failed upstream, the
    same signed event is refused instead of retried (the custodian re-signs)."""
    rotation = test_setup["rotation"]
    real = rotation.author_keys

    def authority_down(leaves):
        raise httpx.ConnectError("authority down")

    monkeypatch.setattr(rotation, "author_keys", authority_down)
    body = _patient_body(test_setup)
    first = test_setup["client"].post(f"/records/{RECORD}/revoke", json=body)
    assert first.status_code == 503
    assert test_setup["repo"].get_lifecycle_state(RECORD) is LifecycleState.GRANTED

    monkeypatch.setattr(rotation, "author_keys", real)
    replay = test_setup["client"].post(f"/records/{RECORD}/revoke", json=body)
    assert replay.status_code == 403
    assert "ReplayedEventError" in replay.json()["detail"]


def test_failed_store_after_claim_restores_the_record(test_setup, monkeypatch):
    """A store failure after the claim puts the state back; the record keeps
    its old ciphertext, which its stored wrapping still opens."""
    repo, attrs = test_setup["repo"], test_setup["attrs"]
    original = repo.get_record(RECORD)
    compiled = repo.get_compiled_policy(original.policy_id)

    def store_down(plan):
        raise RuntimeError("store down")

    monkeypatch.setattr(repo, "apply_rotation", store_down)
    with pytest.raises(RuntimeError, match="store down"):
        test_setup["client"].post(
            f"/records/{RECORD}/revoke", json=_patient_body(test_setup)
        )

    _assert_untouched(test_setup, original)
    assert decrypt_record_via_policy(
        compiled, attrs["attr_keyring"], test_setup["wrapping"], original
    )


def test_undelivered_shares_are_reported_not_hidden(test_setup, monkeypatch):
    """If a share holder is down the revocation still holds, and the response
    says break-glass on the record is closed until it is re-keyed."""
    rotation = test_setup["rotation"]

    def holder_down(*_args):
        raise httpx.ConnectError("custodian down")

    monkeypatch.setattr(rotation, "deposit_shares", holder_down)
    response = test_setup["client"].post(
        f"/records/{RECORD}/revoke", json=_patient_body(test_setup)
    )
    assert response.status_code == 200
    assert response.json()["breakglass_provisioned"] is False
    assert test_setup["repo"].get_lifecycle_state(RECORD) is LifecycleState.REVOKED


def test_no_facility_request_takes_a_private_key_or_dek():
    """Review D6: no facility route accepts a private key or a caller's DEK.

    Every signature is made where the key lives (the custodian) and verified
    here against a certificate; a DEK is only ever unwrapped by the facility
    through the record's policy.
    """
    forbidden = ("private", "signing_key", "old_dek")
    offenders = [
        f"{name}.{field}"
        for name, model in vars(schemas).items()
        if isinstance(model, type)
        and issubclass(model, BaseModel)
        and model.__module__ == schemas.__name__
        for field in model.model_fields
        if any(word in field for word in forbidden)
    ]
    assert offenders == []
