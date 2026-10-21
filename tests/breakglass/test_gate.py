"""Unit tests for the emergency unlock gate (P3-5).

Covers:
- Happy path: exactly THRESHOLD shares unlock and the re-wrapped DEK
  decrypts back to the original plaintext DEK.
- Redundancy: TOTAL_SHARES presented also unlocks.
- Edge cases (P5-4): missing, empty, truncated and garbage shares fail closed.
- Split -> combine round trip for the emergency key itself.
- The emitted TransitionEvent carries EMERGENCY_OPEN.
"""

from __future__ import annotations

import itertools

import pytest
from breakglass.emergency_key import (
    THRESHOLD,
    TOTAL_SHARES,
    generate_emergency_key,
    split_emergency_key,
)
from breakglass.exceptions import InsufficientSharesError
from breakglass.gate import open_emergency_access
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import generate_ec_keypair
from crypto_core.symmetric import aes_gcm_decrypt
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.service import unwrap_dek, wrap_dek
from shamir.exceptions import InvalidShareError
from shamir.split import combine_shares

from tests.transitions import open_event

RECORD_ID = "rec-emergency-001"


@pytest.fixture()
def unlock_scenario():
    """Build one record's DEK wrapped under a fresh 2-of-3 emergency key."""
    dek = b"\x11" * 32
    emergency_key = generate_emergency_key()
    shares = split_emergency_key(emergency_key)

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
        "wrapping": wrapping,
        "lifecycle_priv": lifecycle_priv,
        "lifecycle_pub": lifecycle_pub,
        "pre_pub": pre_pub,
    }


def _unwrap_rewrapped_dek(rewrapped_dek: bytes, pre_priv: int, record_id: str) -> bytes:
    """Test helper: reverse the gate's fixed-length PRE-delivery packing.

    Layout: c1 (32B) || c2 (32B) || nonce (GCM_NONCE_BYTES) || wrapped_dek.
    """
    from contracts.base import GCM_NONCE_BYTES
    from pre.elgamal import decapsulate_key

    field_bytes = 32
    c1 = int.from_bytes(rewrapped_dek[:field_bytes], byteorder="big")
    c2 = int.from_bytes(rewrapped_dek[field_bytes : 2 * field_bytes], byteorder="big")
    offset = 2 * field_bytes
    nonce = rewrapped_dek[offset : offset + GCM_NONCE_BYTES]
    ciphertext = rewrapped_dek[offset + GCM_NONCE_BYTES :]
    delivery_key = decapsulate_key(pre_priv, c1, c2)
    return aes_gcm_decrypt(
        key=delivery_key,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=record_id.encode("utf-8"),
    )


class TestOpenEmergencyAccessHappyPath:
    def test_threshold_shares_unlock_and_dek_matches(self, unlock_scenario):
        pre_priv, pre_pub = generate_pre_keypair()
        result = open_emergency_access(
            shares_presented=unlock_scenario["shares"][:THRESHOLD],
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            transition_event=open_event(
                RECORD_ID,
                LifecycleState.GRANTED,
                "dr-alice",
                ReasonCode.CARDIAC_ARREST,
                unlock_scenario["lifecycle_priv"],
            ),
            actor_public_key=(unlock_scenario["lifecycle_priv"]).public_key(),
            pre_rewrap_key=pre_pub,
        )
        assert result.emergency_key == unlock_scenario["emergency_key"]
        recovered_dek = _unwrap_rewrapped_dek(result.rewrapped_dek, pre_priv, RECORD_ID)
        assert recovered_dek == unlock_scenario["dek"]

    def test_redundant_shares_also_unlock(self, unlock_scenario):
        """All TOTAL_SHARES presented (more than THRESHOLD) still unlocks."""
        assert len(unlock_scenario["shares"]) == TOTAL_SHARES
        pre_priv, pre_pub = generate_pre_keypair()
        result = open_emergency_access(
            shares_presented=unlock_scenario["shares"],
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            transition_event=open_event(
                RECORD_ID,
                LifecycleState.GRANTED,
                "dr-alice",
                ReasonCode.STROKE,
                unlock_scenario["lifecycle_priv"],
            ),
            actor_public_key=(unlock_scenario["lifecycle_priv"]).public_key(),
            pre_rewrap_key=pre_pub,
        )
        recovered_dek = _unwrap_rewrapped_dek(result.rewrapped_dek, pre_priv, RECORD_ID)
        assert recovered_dek == unlock_scenario["dek"]

    def test_unlock_from_revoked_state(self, unlock_scenario):
        """REVOKED -> EMERGENCY_OPEN is also a legal source transition."""
        pre_priv, pre_pub = generate_pre_keypair()
        result = open_emergency_access(
            shares_presented=unlock_scenario["shares"][:THRESHOLD],
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.REVOKED,
            record_id=RECORD_ID,
            transition_event=open_event(
                RECORD_ID,
                LifecycleState.REVOKED,
                "dr-alice",
                ReasonCode.MAJOR_TRAUMA,
                unlock_scenario["lifecycle_priv"],
            ),
            actor_public_key=(unlock_scenario["lifecycle_priv"]).public_key(),
            pre_rewrap_key=pre_pub,
        )
        assert result.transition_event.from_state == LifecycleState.REVOKED


class TestOpenEmergencyAccessEdgeCases:
    """P5-4: missing and malformed shares fail closed, for the right reason."""

    @staticmethod
    def _open(unlock_scenario, shares):
        _, pre_pub = generate_pre_keypair()
        return open_emergency_access(
            shares_presented=shares,
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            transition_event=open_event(
                RECORD_ID,
                LifecycleState.GRANTED,
                "dr-alice",
                ReasonCode.CARDIAC_ARREST,
                unlock_scenario["lifecycle_priv"],
            ),
            actor_public_key=(unlock_scenario["lifecycle_priv"]).public_key(),
            pre_rewrap_key=pre_pub,
        )

    def test_missing_share_fails_closed(self, unlock_scenario):
        """Fewer than THRESHOLD unique shares must not unlock."""
        with pytest.raises(InsufficientSharesError):
            self._open(unlock_scenario, unlock_scenario["shares"][: THRESHOLD - 1])

    def test_no_shares_fails_closed(self, unlock_scenario):
        with pytest.raises(InsufficientSharesError):
            self._open(unlock_scenario, [])

    def test_truncated_share_fails_closed(self, unlock_scenario):
        """A share of the wrong length is rejected by reconstruction.

        Valid shares are presented alongside the malformed one so the
        threshold count is met -- the refusal must come from the malformed
        bytes, not from the share count.
        """
        shares = unlock_scenario["shares"]
        x, share_bytes = shares[1]
        malformed = (x, share_bytes[:-1])
        with pytest.raises(InvalidShareError):
            self._open(unlock_scenario, [shares[0], malformed, shares[2]])

    def test_garbage_share_of_wrong_block_size_fails_closed(self, unlock_scenario):
        xs = [x for x, _ in unlock_scenario["shares"][:THRESHOLD]]
        with pytest.raises(InvalidShareError):
            self._open(unlock_scenario, [(x, b"malformed") for x in xs])


class TestEmergencyKeySplitCombineRoundTrip:
    def test_split_then_combine_recovers_key(self):
        key = generate_emergency_key()
        shares = split_emergency_key(key)
        assert len(shares) == TOTAL_SHARES
        recovered = combine_shares(shares[:THRESHOLD], k=THRESHOLD)
        assert recovered == key

    def test_every_threshold_subset_recovers_key(self):
        """Any THRESHOLD of the TOTAL_SHARES points recover the key; which
        sets the gate accepts is a matter of who holds which point (ADR-0089)."""
        key = generate_emergency_key()
        shares = split_emergency_key(key)
        for subset in itertools.combinations(shares, THRESHOLD):
            assert combine_shares(list(subset), k=THRESHOLD) == key


class TestTransitionEventShape:
    def test_result_transition_event_is_emergency_open(self, unlock_scenario):
        _, pre_pub = generate_pre_keypair()
        result = open_emergency_access(
            shares_presented=unlock_scenario["shares"][:THRESHOLD],
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            transition_event=open_event(
                RECORD_ID,
                LifecycleState.GRANTED,
                "dr-alice",
                ReasonCode.UNCONSCIOUS_PATIENT,
                unlock_scenario["lifecycle_priv"],
            ),
            actor_public_key=(unlock_scenario["lifecycle_priv"]).public_key(),
            pre_rewrap_key=pre_pub,
        )
        assert result.transition_event.to_state == LifecycleState.EMERGENCY_OPEN
        assert result.transition_event.record_id == RECORD_ID
        assert result.transition_event.actor_id == "dr-alice"
        assert result.transition_event.reason_code == ReasonCode.UNCONSCIOUS_PATIENT


def test_unwrap_dek_sanity_matches_original(unlock_scenario):
    """Sanity check on the fixture itself: wrap/unwrap under the emergency key
    round-trips before the gate is ever invoked."""
    unwrapped = unwrap_dek(
        unlock_scenario["wrapping"], unlock_scenario["emergency_key"]
    )
    assert unwrapped == unlock_scenario["dek"]


class TestShareIndexRange:
    """F27: an aliased or zero share index never counts towards the threshold."""

    def _open(self, scenario, shares):
        _, pre_pub = generate_pre_keypair()
        return open_emergency_access(
            shares_presented=shares,
            dek_wrapping=scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            transition_event=open_event(
                RECORD_ID,
                LifecycleState.GRANTED,
                "dr-alice",
                ReasonCode.CARDIAC_ARREST,
                scenario["lifecycle_priv"],
            ),
            actor_public_key=(scenario["lifecycle_priv"]).public_key(),
            pre_rewrap_key=pre_pub,
        )

    def test_share_index_aliasing_rejected(self, unlock_scenario):
        """One share presented as x and x + P must not pass as two shares."""
        from shamir.finite_field import PRIME_MODULUS

        x, share = unlock_scenario["shares"][0]
        # Setup is valid: two genuine shares open the record.
        assert self._open(unlock_scenario, unlock_scenario["shares"][:THRESHOLD])
        with pytest.raises(InvalidShareError, match="outside"):
            self._open(unlock_scenario, [(x, share), (x + PRIME_MODULUS, share)])

    def test_emergency_key_repr_contains_no_key_bytes(self, unlock_scenario):
        """F26: the unlock result's repr never prints the key or wrapped DEK."""
        result = self._open(unlock_scenario, unlock_scenario["shares"][:THRESHOLD])
        text = repr(result)
        for secret in (result.emergency_key, result.rewrapped_dek):
            assert secret.hex() not in text
            assert repr(secret) not in text
