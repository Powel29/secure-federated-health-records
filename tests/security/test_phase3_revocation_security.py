"""Negative security tests for revocation by key-rotation (P3-7, ADR-0036).

Backs the CONVENTIONS.md §5 claim "revoked user cannot decrypt after
re-wrap." Each class states the paper claim it backs and pairs its negative
assertion with a positive control in the same fixture, so a broken setup
cannot masquerade as a passing test (see the ``negative-security-test``
skill).

Adversarial cases proved here:

- Revoked clinician (dropped attribute key) cannot reconstruct the new root
  secret and therefore cannot unwrap the new DEK.
- A cached old DEK cannot decrypt the newly-encrypted ciphertext.
- The old root secret cannot unwrap the new DEK wrapping.
- A tampered `TransitionEvent` is rejected by the state machine.
- A replayed `TransitionEvent` (same event_id) is rejected by the
  consumed-ID store on second apply.
- Illegal transitions around ``REVOKED`` are refused.
"""

from __future__ import annotations

import pytest
from authority.issuance import AttributeAuthority, generate_authority
from contracts import Attribute
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import InvalidSignatureError, generate_ec_keypair
from lifecycle.exceptions import (
    IllegalTransitionError,
    ReplayedEventError,
    StateMismatchError,
)
from lifecycle.state_machine import LifecycleStateMachine, create_transition_event
from policy import reconstruct_root_secret
from policy.exceptions import PolicyDeniedError
from records.exceptions import (
    DecryptionError,
    UnauthorizedRevocationError,
    UnwrappingError,
)
from records.ingest import ingest_record
from records.revocation import revoke_record_access
from records.service import decrypt_record, unwrap_dek

MED_AUTHORITY_ID = "authority-med"
NET_AUTHORITY_ID = "authority-net"


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


def _full_keyring(
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


def _revoked_fixture(patient_id: str, plaintext: bytes):
    """Ingest, revoke, return everything a negative test needs."""
    med, net, clinical = _setup_federation()
    keyring = _full_keyring(med, net, patient_id)
    ingested = ingest_record(
        plaintext=plaintext,
        patient_id=patient_id,
        facility_id="fac-central",
        owner_authority_id=NET_AUTHORITY_ID,
        clinical_policy=clinical,
        attribute_keyring=keyring,
    )
    old_root = reconstruct_root_secret(ingested.compiled_policy, keyring)
    old_dek = unwrap_dek(ingested.dek_wrapping, old_root)
    signing_priv, signing_pub = generate_ec_keypair()
    revoked = revoke_record_access(
        current_record=ingested.record,
        current_wrapping=ingested.dek_wrapping,
        old_dek=old_dek,
        new_clinical_policy=clinical,
        owner_authority_id=NET_AUTHORITY_ID,
        attribute_keyring=keyring,
        actor_id=patient_id,
        actor_signing_key=signing_priv,
        correlation_id=f"rev-{patient_id}",
    )
    return {
        "med": med,
        "net": net,
        "keyring": keyring,
        "ingested": ingested,
        "old_root": old_root,
        "old_dek": old_dek,
        "revoked": revoked,
        "plaintext": plaintext,
        "signing_priv": signing_priv,
        "signing_pub": signing_pub,
        "patient_id": patient_id,
    }


# ---------------------------------------------------------------------------
# Revoked clinician cannot reconstruct the new root secret
# ---------------------------------------------------------------------------


class TestRevokedClinicianCannotReconstruct:
    """Paper claim: a clinician whose attribute keys were dropped from the
    new policy tree cannot reconstruct the new root secret — the policy
    engine fails closed."""

    def test_sec_revoked_user_cannot_decrypt_after_rotation(self) -> None:
        fx = _revoked_fixture("pat-sec-801", b"post-revocation forward secrecy")

        # Positive control: the FULL keyring still reconstructs the NEW
        # root secret (the clinical branch still works when you hold every
        # attribute key). This proves the rotation itself did not break
        # the policy path — only the exclusion of a party would.
        recovered_root = reconstruct_root_secret(
            fx["revoked"].compiled_policy, fx["keyring"]
        )
        assert recovered_root == fx["revoked"].new_root_secret

        # Negative: a clinician who lost the specialty key can no longer
        # satisfy AND(role, specialty) and holds no owner key either.
        # `reconstruct_root_secret` fails closed by raising PolicyDeniedError.
        revoked_clinician_keyring = {
            (MED_AUTHORITY_ID, "role", "physician"): fx["med"].attribute_key(
                "role", "physician"
            ),
            # NO specialty key → clinical AND cannot reconstruct
            # NO owner key    → owner leaf cannot reconstruct
        }
        with pytest.raises(PolicyDeniedError):
            reconstruct_root_secret(
                fx["revoked"].compiled_policy, revoked_clinician_keyring
            )


# ---------------------------------------------------------------------------
# Cached old DEK is useless against the rotated ciphertext
# ---------------------------------------------------------------------------


class TestOldDekCannotDecryptRotated:
    """Paper claim: a cached OLD DEK cannot decrypt the newly-encrypted
    ciphertext — because rotation minted a fresh DEK, not just a re-wrap."""

    def test_sec_old_dek_cannot_decrypt_rotated_record_ciphertext(self) -> None:
        fx = _revoked_fixture("pat-sec-802", b"old DEK must not decrypt new ct")

        # Positive control: old DEK still decrypts the OLD record (rotation
        # doesn't change what the old key could do to old ciphertext).
        recovered_old = decrypt_record(fx["ingested"].record, fx["old_dek"])
        assert recovered_old == fx["plaintext"]

        # Negative: old DEK against NEW ciphertext must fail closed.
        with pytest.raises(DecryptionError):
            decrypt_record(fx["revoked"].rotated_record, fx["old_dek"])


# ---------------------------------------------------------------------------
# Old root secret cannot unwrap the new DEK wrapping
# ---------------------------------------------------------------------------


class TestOldRootCannotUnwrapNewWrapping:
    """Paper claim: the new wrapping is under a fresh root secret; the OLD
    root secret fails AES-GCM authentication."""

    def test_sec_old_root_secret_cannot_unwrap_new_dek_wrapping(self) -> None:
        fx = _revoked_fixture("pat-sec-803", b"old root must not unwrap new")

        # Positive control: old root still unwraps the OLD wrapping.
        assert unwrap_dek(fx["ingested"].dek_wrapping, fx["old_root"]) == fx["old_dek"]

        # Negative: old root against NEW wrapping fails closed.
        with pytest.raises(UnwrappingError):
            unwrap_dek(fx["revoked"].rotated_wrapping, fx["old_root"])


# ---------------------------------------------------------------------------
# Tampered transition event is rejected by the state machine
# ---------------------------------------------------------------------------


class TestTamperedRevocationEventRejected:
    """Paper claim: mutating any field of the signed transition event breaks
    signature verification — the state machine refuses to advance state."""

    def test_sec_tampered_revocation_event_fails_closed(self) -> None:
        fx = _revoked_fixture("pat-sec-804", b"tampered event")
        machine = LifecycleStateMachine()

        # Positive control: untampered event applies cleanly.
        assert (
            machine.apply_transition(
                current_state=LifecycleState.GRANTED,
                event=fx["revoked"].transition_event,
                actor_public_key=fx["signing_pub"],
            )
            == LifecycleState.REVOKED
        )

        # Tamper the actor_id after signing. Use a fresh state machine so
        # the earlier successful consume doesn't confound this test.
        tampered = fx["revoked"].transition_event.model_copy(
            update={"actor_id": "attacker-999"}
        )
        machine2 = LifecycleStateMachine()
        with pytest.raises(InvalidSignatureError):
            machine2.apply_transition(
                current_state=LifecycleState.GRANTED,
                event=tampered,
                actor_public_key=fx["signing_pub"],
            )


# ---------------------------------------------------------------------------
# Replayed transition event is rejected
# ---------------------------------------------------------------------------


class TestReplayedRevocationEventRejected:
    """Paper claim: the consumed-id store rejects a second apply of the
    same event_id — a captured revocation event cannot be re-run to
    re-revoke a re-granted record."""

    def test_sec_replayed_revocation_event_rejected(self) -> None:
        fx = _revoked_fixture("pat-sec-805", b"replay test")
        machine = LifecycleStateMachine()

        # First apply succeeds (positive control).
        machine.apply_transition(
            current_state=LifecycleState.GRANTED,
            event=fx["revoked"].transition_event,
            actor_public_key=fx["signing_pub"],
        )

        # Second apply of the SAME event on a fresh GRANTED state (imagine
        # the record was re-consented and re-issued to GRANTED between)
        # is rejected by the consumed-id store.
        with pytest.raises(ReplayedEventError):
            machine.apply_transition(
                current_state=LifecycleState.GRANTED,
                event=fx["revoked"].transition_event,
                actor_public_key=fx["signing_pub"],
            )


# ---------------------------------------------------------------------------
# Illegal transitions are refused
# ---------------------------------------------------------------------------


class TestIllegalRevocationTransitions:
    """Paper claim: the state machine's ``LEGAL_TRANSITIONS`` frozenset is
    the source of truth for state legality — invented transitions are
    refused."""

    def test_sec_direct_granted_to_expired_refused(self) -> None:
        """GRANTED → EXPIRED is not legal (must pass through EMERGENCY_OPEN)."""
        signing_priv, _ = generate_ec_keypair()
        with pytest.raises(IllegalTransitionError):
            create_transition_event(
                record_id="rec-illegal",
                from_state=LifecycleState.GRANTED,
                to_state=LifecycleState.EXPIRED,
                actor_id="attacker",
                signing_key=signing_priv,
            )

    def test_sec_wrong_current_state_refused(self) -> None:
        """A GRANTED → REVOKED event applied to a REVOKED record is refused
        as a state mismatch (the record is not in GRANTED right now)."""
        signing_priv, signing_pub = generate_ec_keypair()
        event = create_transition_event(
            record_id="rec-mismatch",
            from_state=LifecycleState.GRANTED,
            to_state=LifecycleState.REVOKED,
            actor_id="pat-mismatch",
            signing_key=signing_priv,
        )
        machine = LifecycleStateMachine()

        # Positive control: applies to GRANTED.
        assert (
            machine.apply_transition(
                current_state=LifecycleState.GRANTED,
                event=event,
                actor_public_key=signing_pub,
            )
            == LifecycleState.REVOKED
        )

        # Negative: same event applied to REVOKED (already-revoked) fails.
        machine2 = LifecycleStateMachine()
        with pytest.raises(StateMismatchError):
            machine2.apply_transition(
                current_state=LifecycleState.REVOKED,
                event=event,
                actor_public_key=signing_pub,
            )


class TestRevocationAuthorizationSecurity:
    """Negative security tests for who-may-revoke authorization (P3-12).

    Claim: Revocation is restricted to the record owner (patient) or its home
    authority. A correctly-signed request from an unauthorized party (e.g. a
    clinician or foreign authority) fails closed and rotates nothing.
    """

    def test_sec_clinician_cannot_revoke_patient_record(self) -> None:
        """A clinician holding a valid ECDSA key pair cannot revoke a patient's
        record. The call fails closed with UnauthorizedRevocationError."""
        patient_id = "pat-sec-auth-1"
        plaintext = b"sensitive medical history"
        ingested = ingest_record(
            plaintext=plaintext,
            patient_id=patient_id,
            facility_id="fac-central",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="role", value="physician"),
                authority_id=MED_AUTHORITY_ID,
            ),
            attribute_keyring={
                (MED_AUTHORITY_ID, "role", "physician"): b"k" * 32,
                (NET_AUTHORITY_ID, "owner", patient_id): b"o" * 32,
            },
        )
        old_dek = b"d" * 32  # caller holding old dek

        clinician_priv, _ = generate_ec_keypair()
        # Negative test: Clinician signs with valid ECDSA key,
        # but actor_id is clinician.
        with pytest.raises(
            UnauthorizedRevocationError, match="not authorized to revoke"
        ):
            revoke_record_access(
                current_record=ingested.record,
                current_wrapping=ingested.dek_wrapping,
                old_dek=old_dek,
                new_clinical_policy=ingested.policy_tree,
                owner_authority_id=NET_AUTHORITY_ID,
                attribute_keyring={
                    (MED_AUTHORITY_ID, "role", "physician"): b"k" * 32,
                    (NET_AUTHORITY_ID, "owner", patient_id): b"o" * 32,
                },
                actor_id="clinician-dr-mallory",
                actor_signing_key=clinician_priv,
                correlation_id="rev-sec-clinician",
            )

    def test_sec_foreign_authority_cannot_revoke_patient_record(self) -> None:
        """A foreign attribute authority (e.g. authority-med) cannot revoke a
        record whose home authority is authority-net."""
        patient_id = "pat-sec-auth-2"
        plaintext = b"foreign authority revocation test"
        ingested = ingest_record(
            plaintext=plaintext,
            patient_id=patient_id,
            facility_id="fac-central",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=PolicyTree(
                node_type=PolicyNodeType.LEAF,
                attribute=Attribute(name="role", value="physician"),
                authority_id=MED_AUTHORITY_ID,
            ),
            attribute_keyring={
                (MED_AUTHORITY_ID, "role", "physician"): b"k" * 32,
                (NET_AUTHORITY_ID, "owner", patient_id): b"o" * 32,
            },
        )
        old_dek = b"d" * 32

        foreign_auth_priv, _ = generate_ec_keypair()

        with pytest.raises(
            UnauthorizedRevocationError, match="not authorized to revoke"
        ):
            revoke_record_access(
                current_record=ingested.record,
                current_wrapping=ingested.dek_wrapping,
                old_dek=old_dek,
                new_clinical_policy=ingested.policy_tree,
                owner_authority_id=NET_AUTHORITY_ID,
                attribute_keyring={
                    (MED_AUTHORITY_ID, "role", "physician"): b"k" * 32,
                    (NET_AUTHORITY_ID, "owner", patient_id): b"o" * 32,
                },
                actor_id=MED_AUTHORITY_ID,
                actor_signing_key=foreign_auth_priv,
                correlation_id="rev-sec-foreign",
            )

    def test_sec_positive_control_patient_and_home_authority_can_revoke(self) -> None:
        """Positive control: The patient or their home authority with valid keys
        successfully revokes the record."""
        patient_id = "pat-sec-auth-3"
        plaintext = b"positive control revocation payload"
        fix = _revoked_fixture(patient_id, plaintext)

        # In _revoked_fixture, actor_id was patient_id -> success!
        assert fix["revoked"].transition_event.actor_id == patient_id
        assert fix["revoked"].rotated_wrapping.generation == 1

        # Now test home authority as actor:
        net_priv, _ = generate_ec_keypair()
        second_revocation = revoke_record_access(
            current_record=fix["revoked"].rotated_record,
            current_wrapping=fix["revoked"].rotated_wrapping,
            old_dek=unwrap_dek(
                fix["revoked"].rotated_wrapping, fix["revoked"].new_root_secret
            ),
            new_clinical_policy=fix["revoked"].policy_tree,
            owner_authority_id=NET_AUTHORITY_ID,
            attribute_keyring=fix["keyring"],
            actor_id=NET_AUTHORITY_ID,
            actor_signing_key=net_priv,
            correlation_id="rev-sec-home-auth-positive",
        )
        assert second_revocation.transition_event.actor_id == NET_AUTHORITY_ID
        assert second_revocation.rotated_wrapping.generation == 2
