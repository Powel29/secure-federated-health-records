"""Negative security tests for P3-5 emergency unlock gate.

Backs the P3-5 exit criteria: break-glass is a genuine 2-of-3 threshold, not
a single custodian's decision, and every failure mode fails closed.

Each test states the paper claim it backs and includes a positive control in
the same fixture so a broken setup cannot masquerade as a passing test.

Adversarial cases proved here:

- A single share (any one custodian) is never enough to open a record.
- The audit service's share alone cannot unilaterally open a record --
  headline claim: audit participates, it does not decide.
- Duplicate share IDs (the same x-coordinate presented twice) do not count
  as two distinct shares.
- Tampered share bytes reconstruct the wrong emergency key, and the wrong
  key fails to authenticate the record's DEK wrapping downstream.
- The emitted TransitionEvent is signature-verifiable and legal per the
  lifecycle state machine -- an emergency open is not an unsigned side effect.
"""

from __future__ import annotations

import pytest
from breakglass.emergency_key import (
    generate_emergency_key,
    split_emergency_key,
)
from breakglass.exceptions import InsufficientSharesError
from breakglass.gate import open_emergency_access
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import generate_ec_keypair
from lifecycle.state_machine import (
    ConsumedEventIds,
    LifecycleStateMachine,
    verify_transition_event,
)
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.exceptions import UnwrappingError
from records.service import wrap_dek
from shamir.exceptions import SecretSharingError

RECORD_ID = "rec-emergency-security-001"


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def scenario():
    """One record's DEK wrapped under a fresh 2-of-3 emergency key, plus the
    signing/PRE key material a gate call needs."""
    dek = b"\x22" * 32
    emergency_key = generate_emergency_key()
    shares = split_emergency_key(emergency_key)  # [(1, ...), (2, ...), (3, ...)]

    wrapping = wrap_dek(
        dek=dek,
        record_id=RECORD_ID,
        wrapping_key=emergency_key,
        wrapped_for="emergency",
    )

    lifecycle_priv, lifecycle_pub = generate_ec_keypair()
    _, pre_pub = generate_pre_keypair()

    return {
        "dek": dek,
        "emergency_key": emergency_key,
        "shares": shares,
        # Convention for these tests: shares[0]=facility, shares[1]=home
        # authority, shares[2]=audit service.
        "facility_share": shares[0],
        "authority_share": shares[1],
        "audit_share": shares[2],
        "wrapping": wrapping,
        "lifecycle_priv": lifecycle_priv,
        "lifecycle_pub": lifecycle_pub,
        "pre_pub": pre_pub,
    }


def _open(scenario, shares_presented, **overrides):
    """Helper: call open_emergency_access with sane defaults."""
    defaults = dict(
        shares_presented=shares_presented,
        dek_wrapping=scenario["wrapping"],
        transition_source_state=LifecycleState.GRANTED,
        record_id=RECORD_ID,
        actor_id="dr-alice",
        correlation_id="corr-security-001",
        reason_code=ReasonCode.CARDIAC_ARREST,
        lifecycle_signing_key=scenario["lifecycle_priv"],
        pre_rewrap_key=scenario["pre_pub"],
    )
    defaults.update(overrides)
    return open_emergency_access(**defaults)


# ---------------------------------------------------------------------------
# Single-share rejection
# ---------------------------------------------------------------------------


class TestSingleShareRejected:
    """Paper claim: one share, from any single custodian, cannot open a record."""

    def test_positive_control_two_shares_unlock(self, scenario):
        two = [scenario["facility_share"], scenario["authority_share"]]
        result = _open(scenario, two)
        assert result.emergency_key == scenario["emergency_key"]

    @pytest.mark.claim("C3", level="module")
    def test_single_facility_share_rejected(self, scenario):
        with pytest.raises(InsufficientSharesError):
            _open(scenario, [scenario["facility_share"]])

    @pytest.mark.claim("C3", level="module")
    def test_single_authority_share_rejected(self, scenario):
        with pytest.raises(InsufficientSharesError):
            _open(scenario, [scenario["authority_share"]])


# ---------------------------------------------------------------------------
# Audit service cannot unilaterally open (headline claim)
# ---------------------------------------------------------------------------


class TestAuditShareAloneCannotOpen:
    """Paper claim: audit participates in break-glass, it does not decide.

    The audit service holds one of three shares -- exactly like any other
    custodian -- and its share alone is exactly as insufficient as anyone
    else's lone share. This is the property that keeps break-glass a
    threshold decision rather than a standing audit override.
    """

    def test_positive_control_audit_plus_one_more_unlocks(self, scenario):
        """Audit's share IS useful as one of two -- just never alone."""
        result = _open(scenario, [scenario["audit_share"], scenario["facility_share"]])
        assert result.emergency_key == scenario["emergency_key"]

    @pytest.mark.claim("C3", level="module")
    def test_audit_share_alone_rejected(self, scenario):
        with pytest.raises(InsufficientSharesError):
            _open(scenario, [scenario["audit_share"]])


# ---------------------------------------------------------------------------
# Duplicate share IDs do not count twice
# ---------------------------------------------------------------------------


class TestDuplicateSharesDoNotCount:
    """Paper claim: presenting one share twice is not two shares."""

    def test_positive_control_two_distinct_shares_unlock(self, scenario):
        result = _open(scenario, [scenario["facility_share"], scenario["audit_share"]])
        assert result.emergency_key == scenario["emergency_key"]

    def test_same_share_twice_rejected(self, scenario):
        with pytest.raises(InsufficientSharesError):
            _open(scenario, [scenario["facility_share"], scenario["facility_share"]])

    def test_same_x_different_payload_rejected(self, scenario):
        """Even a mutated copy of a share x-coordinate does not add a second
        distinct share -- uniqueness is by x, and a duplicate x is discarded
        before reconstruction is attempted at all."""
        x, share_bytes = scenario["facility_share"]
        forged_same_x = (x, b"\x00" * len(share_bytes))
        with pytest.raises(InsufficientSharesError):
            _open(scenario, [scenario["facility_share"], forged_same_x])


# ---------------------------------------------------------------------------
# Tampered share bytes
# ---------------------------------------------------------------------------


class TestTamperedShareBytes:
    """Paper claim: a corrupted share reconstructs the wrong key, and the
    wrong key is caught downstream rather than silently accepted."""

    def test_positive_control_untampered_shares_unlock(self, scenario):
        two = [scenario["facility_share"], scenario["authority_share"]]
        result = _open(scenario, two)
        assert result.emergency_key == scenario["emergency_key"]

    def test_tampered_share_bytes_fail_downstream(self, scenario):
        x, share_bytes = scenario["facility_share"]
        tampered_bytes = bytes([share_bytes[0] ^ 0xFF]) + share_bytes[1:]
        tampered_share = (x, tampered_bytes)

        # Reconstruction with the tampered share either produces the wrong
        # 32-byte key (caught when it fails to authenticate the DEK wrapping)
        # or fails structurally inside shamir -- both are "fails closed".
        with pytest.raises((SecretSharingError, UnwrappingError)):
            _open(scenario, [tampered_share, scenario["authority_share"]])


# ---------------------------------------------------------------------------
# Emitted transition event integrity
# ---------------------------------------------------------------------------


class TestEmittedTransitionEventIntegrity:
    """Paper claim: the emergency-open transition is a signed, verifiable,
    legal artefact -- not an unsigned side effect of the gate."""

    def test_positive_control_unlock_succeeds(self, scenario):
        two = [scenario["facility_share"], scenario["authority_share"]]
        result = _open(scenario, two)
        assert result.transition_event.to_state == LifecycleState.EMERGENCY_OPEN

    def test_transition_event_signature_verifies(self, scenario):
        two = [scenario["facility_share"], scenario["authority_share"]]
        result = _open(scenario, two)
        # Should not raise.
        verify_transition_event(result.transition_event, scenario["lifecycle_pub"])

    def test_transition_event_is_legal_per_state_machine(self, scenario):
        two = [scenario["facility_share"], scenario["authority_share"]]
        result = _open(scenario, two)
        machine = LifecycleStateMachine(ConsumedEventIds())
        new_state = machine.apply_transition(
            current_state=LifecycleState.GRANTED,
            event=result.transition_event,
            actor_public_key=scenario["lifecycle_pub"],
        )
        assert new_state == LifecycleState.EMERGENCY_OPEN

    def test_tampered_transition_event_signature_fails(self, scenario):
        from crypto_core import InvalidSignatureError

        two = [scenario["facility_share"], scenario["authority_share"]]
        result = _open(scenario, two)
        tampered = result.transition_event.model_copy(update={"actor_id": "dr-evil"})
        with pytest.raises(InvalidSignatureError):
            verify_transition_event(tampered, scenario["lifecycle_pub"])
