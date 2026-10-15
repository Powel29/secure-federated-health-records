"""Unit tests for the Hospital Node Revocation endpoint (P4-1, P3-7, P3-12).

Verifies:
- An authorized patient's signed event rotates the record DEK, updates the
  wrapping generation and moves the lifecycle to REVOKED.
- The request carries no private key and no DEK (review D6): the event is
  verified against the patient's certificate, and the facility unwraps the
  current DEK through the record's policy.
- Unauthorized, forged, stale and replayed events are refused.
"""

from __future__ import annotations

import datetime

import pytest
from api import schemas
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import Attribute, PolicyTree
from crypto_core import certificate_to_pem, generate_ec_keypair
from lifecycle.state_machine import create_transition_event
from policy.engine import decrypt_record_via_policy
from pydantic import BaseModel


def _event(signing_key, actor_id="patient-001", issued_at=None):
    return create_transition_event(
        record_id="rec-001",
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=actor_id,
        signing_key=signing_key,
        issued_at=issued_at,
    )


def _body(test_setup, event, certificate_pem=None):
    attrs = test_setup["attrs"]
    return {
        "transition_event": event.model_dump(mode="json"),
        "actor_certificate_pem": certificate_pem or test_setup["pki"]["pat_cert_pem"],
        "new_clinical_policy": PolicyTree(
            node_type=PolicyNodeType.LEAF,
            attribute=Attribute(name="role", value="physician"),
            authority_id="authority-med",
        ).model_dump(mode="json"),
        "owner_authority_id": "authority-net",
        "attribute_keyring": attrs["b64_keyring"],
        "correlation_id": "corr-rev-001",
    }


class TestHospitalRevocationEndpoint:
    """Test suite for POST /records/{record_id}/revoke."""

    def test_authorized_patient_revokes_access(self, test_setup):
        """Patient revokes access: rotates DEK and advances lifecycle to REVOKED."""
        client = test_setup["client"]
        repo = test_setup["repo"]
        old_wrapping = test_setup["wrapping"]

        response = client.post(
            "/records/rec-001/revoke",
            json=_body(test_setup, _event(test_setup["pki"]["pat_priv"])),
        )

        assert response.status_code == 200, response.text
        data = response.json()
        assert data["record_id"] == "rec-001"
        assert data["new_generation"] == old_wrapping.generation + 1
        assert data["transition_event"]["from_state"] == LifecycleState.GRANTED.value
        assert data["transition_event"]["to_state"] == LifecycleState.REVOKED.value
        assert repo.get_lifecycle_state("rec-001") == LifecycleState.REVOKED

    def test_unauthorized_clinician_cannot_revoke(self, test_setup):
        """A clinician's own signed event is refused (P3-12 -> 403)."""
        client = test_setup["client"]
        event = _event(test_setup["pki"]["alice_priv"], actor_id="dr-alice")

        response = client.post("/records/rec-001/revoke", json=_body(test_setup, event))

        assert response.status_code == 403
        assert "Unauthorized revocation" in response.json()["detail"]
        assert test_setup["repo"].get_lifecycle_state("rec-001") == (
            LifecycleState.GRANTED
        )

    def test_event_signed_by_another_key_is_refused(self, test_setup):
        """An event naming the patient but signed by someone else does not
        verify against the patient's certificate (400, nothing rotated)."""
        client = test_setup["client"]
        attacker, _ = generate_ec_keypair()

        response = client.post(
            "/records/rec-001/revoke", json=_body(test_setup, _event(attacker))
        )

        assert response.status_code == 400
        assert "Revocation failed" in response.json()["detail"]
        assert test_setup["repo"].get_lifecycle_state("rec-001") == (
            LifecycleState.GRANTED
        )

    def test_certificate_of_another_patient_is_refused(self, test_setup):
        """A clinician certificate cannot stand in for the patient's (403)."""
        client = test_setup["client"]
        event = _event(test_setup["pki"]["pat_priv"])

        response = client.post(
            "/records/rec-001/revoke",
            json=_body(
                test_setup,
                event,
                certificate_to_pem(test_setup["pki"]["alice_cert"]).decode("ascii"),
            ),
        )

        assert response.status_code == 403

    def test_stale_event_is_refused(self, test_setup):
        """An old signed revocation cannot be held back and replayed later."""
        client = test_setup["client"]
        old = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        event = _event(test_setup["pki"]["pat_priv"], issued_at=old)

        response = client.post("/records/rec-001/revoke", json=_body(test_setup, event))

        assert response.status_code == 400
        assert "not recent" in response.json()["detail"]

    def test_replayed_event_is_refused(self, test_setup):
        """The event id is one-time: re-sending the same event is refused."""
        client = test_setup["client"]
        repo = test_setup["repo"]
        event = _event(test_setup["pki"]["pat_priv"])
        assert client.post(
            "/records/rec-001/revoke", json=_body(test_setup, event)
        ).status_code == (200)
        # Re-consent puts the record back to GRANTED; the old event must
        # still not revoke it again.
        repo.transition_lifecycle_state(
            "rec-001", expected=LifecycleState.REVOKED, new=LifecycleState.GRANTED
        )

        response = client.post("/records/rec-001/revoke", json=_body(test_setup, event))

        assert response.status_code == 400
        assert "replayed" in response.json()["detail"]

    def test_failed_write_after_claim_restores_the_record(
        self, test_setup, monkeypatch
    ):
        """A write failing after the rotated ciphertext was stored puts the old
        ciphertext back with the state, so the record still opens under its
        stored wrapping (no record left under a DEK nothing unwraps)."""
        client = test_setup["client"]
        repo = test_setup["repo"]
        attrs = test_setup["attrs"]
        original = repo.get_record("rec-001")
        compiled = repo.get_compiled_policy(original.policy_id)

        def store_down(wrapping):
            raise RuntimeError("store down")

        monkeypatch.setattr(repo, "insert_dek_wrapping", store_down)
        with pytest.raises(RuntimeError, match="store down"):
            client.post(
                "/records/rec-001/revoke",
                json=_body(test_setup, _event(test_setup["pki"]["pat_priv"])),
            )

        assert repo.get_lifecycle_state("rec-001") == LifecycleState.GRANTED
        assert repo.get_record("rec-001") == original
        assert decrypt_record_via_policy(
            compiled, attrs["attr_keyring"], test_setup["wrapping"], original
        )


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
