"""Unit tests for revocation by key-rotation (P3-7, ADR-0036).

Happy-path coverage: DEK rotation, generation increment, patient owner-leaf
preservation, and the re-consent path (REVOKED → GRANTED). Adversarial cases
live in ``tests/security/test_phase3_revocation_security.py``.
"""

from __future__ import annotations

import pytest
from authority.issuance import AttributeAuthority, generate_authority
from contracts import Attribute
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import generate_ec_keypair
from lifecycle.state_machine import LifecycleStateMachine, create_transition_event
from policy import reconstruct_root_secret
from policy.exceptions import PolicyDeniedError
from records.exceptions import UnauthorizedRevocationError
from records.ingest import ingest_record
from records.revocation import (
    RevocationResult,
    check_revocation_authorization,
    revoke_record_access,
)
from records.service import decrypt_record, unwrap_dek

MED_AUTHORITY_ID = "authority-med"
NET_AUTHORITY_ID = "authority-net"


def _signed_revocation(record, actor_id, signing_key):
    """The actor's signed GRANTED -> REVOKED event and the key it verifies by.

    Revocation takes a pre-signed event (review D6): the signer's private key
    never reaches ``revoke_record_access``.
    """
    event = create_transition_event(
        record_id=record.record_id,
        from_state=LifecycleState.GRANTED,
        to_state=LifecycleState.REVOKED,
        actor_id=actor_id,
        signing_key=signing_key,
    )
    return {"transition_event": event, "actor_public_key": signing_key.public_key()}


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _setup_federation() -> tuple[AttributeAuthority, AttributeAuthority, PolicyTree]:
    med = generate_authority(MED_AUTHORITY_ID, frozenset({"role"}))
    net = generate_authority(NET_AUTHORITY_ID, frozenset({"specialty", "owner"}))
    clinical = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", MED_AUTHORITY_ID),
            _leaf("specialty", "cardiology", NET_AUTHORITY_ID),
        ),
    )
    return med, net, clinical


def _authoring_keyring(
    med: AttributeAuthority,
    net: AttributeAuthority,
    patient_id: str,
) -> dict[tuple[str, str, str], bytes]:
    return {
        (MED_AUTHORITY_ID, "role", "physician"): med.attribute_key("role", "physician"),
        (NET_AUTHORITY_ID, "specialty", "cardiology"): net.attribute_key(
            "specialty", "cardiology"
        ),
        (NET_AUTHORITY_ID, "owner", patient_id): net.attribute_key("owner", patient_id),
    }


def _fresh_ingest(patient_id: str, plaintext: bytes):
    """Ingest a record and return (result, keyring, med, net, clinical)."""
    med, net, clinical = _setup_federation()
    keyring = _authoring_keyring(med, net, patient_id)
    result = ingest_record(
        plaintext=plaintext,
        patient_id=patient_id,
        facility_id="fac-central",
        owner_authority_id=NET_AUTHORITY_ID,
        clinical_policy=clinical,
        attribute_keyring=keyring,
    )
    return result, keyring, med, net, clinical


class TestRotationMechanics:
    """The crypto rotation itself: fresh DEK, fresh wrapping, generation++."""

    def test_revocation_rotates_dek_and_increments_generation(self) -> None:
        """Rotation produces new ciphertext and generation = old + 1."""
        patient_id = "pat-701"
        plaintext = b"cardiac readings, revocation test"
        ingested, keyring, _, _, clinical = _fresh_ingest(patient_id, plaintext)

        # Rotate — the new clinical policy stays the same (this test isolates
        # the crypto rotation; the "kick a party out" case is in the security
        # suite via a stripped keyring).
        signing_priv, _ = generate_ec_keypair()
        result = revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            current_compiled_policy=ingested.compiled_policy,
            new_clinical_policy=clinical,
            owner_authority_id=NET_AUTHORITY_ID,
            attribute_keyring=keyring,
            **_signed_revocation(ingested.record, "pat-701", signing_priv),
            correlation_id="rev-flow-701",
        )

        assert isinstance(result, RevocationResult)
        old_gen = ingested.dek_wrapping.generation
        assert result.rotated_wrapping.generation == old_gen + 1
        assert result.rotated_record.ciphertext != ingested.record.ciphertext
        assert result.rotated_record.record_id == ingested.record.record_id
        assert result.rotated_record.policy_id != ingested.record.policy_id
        assert result.audit_payload["old_generation"] == 0
        assert result.audit_payload["new_generation"] == 1

    def test_rotated_record_round_trips_via_new_root_secret(self) -> None:
        """The new DEK, unwrapped from the new wrapping, decrypts the new ciphertext."""
        patient_id = "pat-702"
        plaintext = b"round-trip revocation test payload"
        ingested, keyring, _, _, clinical = _fresh_ingest(patient_id, plaintext)

        signing_priv, _ = generate_ec_keypair()
        result = revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            current_compiled_policy=ingested.compiled_policy,
            new_clinical_policy=clinical,
            owner_authority_id=NET_AUTHORITY_ID,
            attribute_keyring=keyring,
            **_signed_revocation(ingested.record, "pat-702", signing_priv),
            correlation_id="rev-flow-702",
        )

        new_dek = unwrap_dek(result.rotated_wrapping, result.new_root_secret)
        recovered = decrypt_record(result.rotated_record, new_dek)
        assert recovered == plaintext


class TestTransitionEvent:
    """The signed lifecycle event: shape, signature, and state-machine legality."""

    def test_revocation_emits_valid_signed_transition_event(self) -> None:
        """The emitted event is signed and legal per the state machine."""
        patient_id = "pat-703"
        plaintext = b"transition event test"
        ingested, keyring, _, _, clinical = _fresh_ingest(patient_id, plaintext)

        signing_priv, signing_pub = generate_ec_keypair()
        result = revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            current_compiled_policy=ingested.compiled_policy,
            new_clinical_policy=clinical,
            owner_authority_id=NET_AUTHORITY_ID,
            attribute_keyring=keyring,
            **_signed_revocation(ingested.record, "pat-703", signing_priv),
            correlation_id="rev-flow-703",
        )

        assert result.transition_event.from_state == LifecycleState.GRANTED
        assert result.transition_event.to_state == LifecycleState.REVOKED
        assert result.transition_event.actor_id == "pat-703"

        # The state machine accepts and consumes the event.
        machine = LifecycleStateMachine()
        new_state = machine.apply_transition(
            current_state=LifecycleState.GRANTED,
            event=result.transition_event,
            actor_public_key=signing_pub,
        )
        assert new_state == LifecycleState.REVOKED

    def test_re_consent_path_revoked_to_granted(self) -> None:
        """After revocation the state machine accepts REVOKED → GRANTED (re-consent)."""
        patient_id = "pat-704"
        signing_priv, signing_pub = generate_ec_keypair()

        # Manually construct the re-consent event; the rotation itself isn't
        # exercised here (that would be a fresh grant, not a P3-7 concern).
        reconsent = create_transition_event(
            record_id="rec-reconsent-704",
            from_state=LifecycleState.REVOKED,
            to_state=LifecycleState.GRANTED,
            actor_id=patient_id,
            signing_key=signing_priv,
        )

        machine = LifecycleStateMachine()
        new_state = machine.apply_transition(
            current_state=LifecycleState.REVOKED,
            event=reconsent,
            actor_public_key=signing_pub,
        )
        assert new_state == LifecycleState.GRANTED


class TestOwnerLeafPreserved:
    """Patient self-access via ADR-0016 owner leaf survives revocation."""

    def test_patient_owner_leaf_preserved_across_revocation(self) -> None:
        """After revocation the patient can still decrypt via their owner leaf."""
        patient_id = "pat-705"
        plaintext = b"patient should still be able to read this"
        ingested, keyring, med, net, clinical = _fresh_ingest(patient_id, plaintext)

        signing_priv, _ = generate_ec_keypair()
        result = revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            current_compiled_policy=ingested.compiled_policy,
            new_clinical_policy=clinical,
            owner_authority_id=NET_AUTHORITY_ID,
            attribute_keyring=keyring,
            **_signed_revocation(ingested.record, patient_id, signing_priv),
            correlation_id="rev-flow-705",
        )

        # The patient path: hold ONLY the owner key. No clinical attributes.
        patient_only_keyring: dict[tuple[str, str, str], bytes] = {
            (NET_AUTHORITY_ID, "owner", patient_id): net.attribute_key(
                "owner", patient_id
            ),
        }
        # Sanity: without the owner leaf the reconstruction fails closed.
        empty_keyring: dict[tuple[str, str, str], bytes] = {}
        with pytest.raises(PolicyDeniedError):
            reconstruct_root_secret(result.compiled_policy, empty_keyring)

        # With just the owner key the patient reconstructs and decrypts.
        recovered_root = reconstruct_root_secret(
            result.compiled_policy, patient_only_keyring
        )
        recovered_dek = unwrap_dek(result.rotated_wrapping, recovered_root)
        recovered_plaintext = decrypt_record(result.rotated_record, recovered_dek)
        assert recovered_plaintext == plaintext


class TestRevocationAuthorization:
    """Authorization checks for who is allowed to revoke (P3-12)."""

    def test_patient_authorized_to_revoke(self) -> None:
        """The record's owner (patient) is authorized to revoke."""
        patient_id = "pat-auth-701"
        ingested, _, _, _, _ = _fresh_ingest(patient_id, b"auth test payload")
        # Should not raise:
        check_revocation_authorization(
            actor_id=patient_id,
            record=ingested.record,
            owner_authority_id=NET_AUTHORITY_ID,
        )

    def test_home_authority_authorized_to_revoke(self) -> None:
        """The record's home authority is authorized to revoke."""
        patient_id = "pat-auth-702"
        ingested, _, _, _, _ = _fresh_ingest(patient_id, b"auth test payload")
        # Should not raise:
        check_revocation_authorization(
            actor_id=NET_AUTHORITY_ID,
            record=ingested.record,
            owner_authority_id=NET_AUTHORITY_ID,
        )

    def test_clinician_unauthorized_to_revoke(self) -> None:
        """A clinician is unauthorized to revoke a patient's record."""
        patient_id = "pat-auth-703"
        ingested, _, _, _, _ = _fresh_ingest(patient_id, b"auth test payload")
        with pytest.raises(
            UnauthorizedRevocationError, match="not authorized to revoke"
        ):
            check_revocation_authorization(
                actor_id="clinician-dr-smith",
                record=ingested.record,
                owner_authority_id=NET_AUTHORITY_ID,
            )

    def test_foreign_authority_unauthorized_to_revoke(self) -> None:
        """A foreign authority (not the patient's home authority) is unauthorized."""
        patient_id = "pat-auth-704"
        ingested, _, _, _, _ = _fresh_ingest(patient_id, b"auth test payload")
        with pytest.raises(
            UnauthorizedRevocationError, match="not authorized to revoke"
        ):
            check_revocation_authorization(
                actor_id=MED_AUTHORITY_ID,
                record=ingested.record,
                owner_authority_id=NET_AUTHORITY_ID,
            )

    def test_another_patient_unauthorized_to_revoke(self) -> None:
        """Another patient is unauthorized to revoke a different patient's record."""
        patient_id = "pat-auth-705"
        ingested, _, _, _, _ = _fresh_ingest(patient_id, b"auth test payload")
        with pytest.raises(
            UnauthorizedRevocationError, match="not authorized to revoke"
        ):
            check_revocation_authorization(
                actor_id="pat-stranger-999",
                record=ingested.record,
                owner_authority_id=NET_AUTHORITY_ID,
            )

    def test_revoke_record_access_by_home_authority_succeeds(self) -> None:
        """Revocation executed by the home authority succeeds and rotates the DEK."""
        patient_id = "pat-auth-706"
        plaintext = b"home authority revocation test"
        ingested, keyring, _, net, clinical = _fresh_ingest(patient_id, plaintext)

        result = revoke_record_access(
            current_record=ingested.record,
            current_wrapping=ingested.dek_wrapping,
            current_compiled_policy=ingested.compiled_policy,
            new_clinical_policy=clinical,
            owner_authority_id=NET_AUTHORITY_ID,
            attribute_keyring=keyring,
            **_signed_revocation(ingested.record, NET_AUTHORITY_ID, net.private_key),
            correlation_id="rev-home-auth-706",
        )

        assert isinstance(result, RevocationResult)
        assert result.transition_event.actor_id == NET_AUTHORITY_ID
        assert (
            result.rotated_wrapping.generation == ingested.dek_wrapping.generation + 1
        )

    def test_revoke_record_access_by_unauthorized_actor_fails_closed(self) -> None:
        """Revocation attempted by an unauthorized clinician fails closed."""
        patient_id = "pat-auth-707"
        plaintext = b"clinician unauthorized revocation test"
        ingested, keyring, _, _, clinical = _fresh_ingest(patient_id, plaintext)

        clinician_priv, _ = generate_ec_keypair()
        with pytest.raises(
            UnauthorizedRevocationError, match="not authorized to revoke"
        ):
            revoke_record_access(
                current_record=ingested.record,
                current_wrapping=ingested.dek_wrapping,
                current_compiled_policy=ingested.compiled_policy,
                new_clinical_policy=clinical,
                owner_authority_id=NET_AUTHORITY_ID,
                attribute_keyring=keyring,
                **_signed_revocation(
                    ingested.record, "clinician-dr-mallory", clinician_priv
                ),
                correlation_id="rev-malicious-707",
            )
