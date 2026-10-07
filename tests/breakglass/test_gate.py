"""Unit tests for the emergency unlock gate (P3-5).

Covers:
- Happy path: exactly THRESHOLD shares unlock and the re-wrapped DEK
  decrypts back to the original plaintext DEK.
- Redundancy: TOTAL_SHARES presented also unlocks.
- Split -> combine round trip for the emergency key itself.
- The emitted TransitionEvent carries EMERGENCY_OPEN.
"""

from __future__ import annotations
from breakglass.exceptions import InsufficientSharesError
import pytest
from breakglass.emergency_key import (
    THRESHOLD,
    TOTAL_SHARES,
    generate_emergency_key,
    split_emergency_key,
)
from breakglass.gate import open_emergency_access
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import generate_ec_keypair
from crypto_core.symmetric import aes_gcm_decrypt
from pre.elgamal import generate_keypair as generate_pre_keypair
from records.service import unwrap_dek, wrap_dek
from shamir.split import combine_shares

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
            actor_id="dr-alice",
            correlation_id="corr-001",
            reason_code=ReasonCode.CARDIAC_ARREST,
            lifecycle_signing_key=unlock_scenario["lifecycle_priv"],
            pre_rewrap_key=pre_pub,
        )
        assert result.emergency_key == unlock_scenario["emergency_key"]
        recovered_dek = _unwrap_rewrapped_dek(result.rewrapped_dek, pre_priv, RECORD_ID)
        assert recovered_dek == unlock_scenario["dek"]
    def test_missing_share_fails_closed(self, unlock_scenario):
        """Fewer than THRESHOLD unique shares must not unlock."""
        _, pre_pub = generate_pre_keypair()

        with pytest.raises(InsufficientSharesError):
            open_emergency_access(
                shares_presented=unlock_scenario["shares"][: THRESHOLD - 1],
                dek_wrapping=unlock_scenario["wrapping"],
                transition_source_state=LifecycleState.GRANTED,
                record_id=RECORD_ID,
                actor_id="dr-alice",
                correlation_id="corr-missing-share",
                reason_code=ReasonCode.CARDIAC_ARREST,
                lifecycle_signing_key=unlock_scenario["lifecycle_priv"],
                pre_rewrap_key=pre_pub,
            )

    def test_malformed_share_fails_closed(self, unlock_scenario):
        """Malformed share data must not unlock emergency access."""
        _, pre_pub = generate_pre_keypair()

        with pytest.raises(Exception):
            open_emergency_access(
                shares_presented=[(1, b"malformed")],
                dek_wrapping=unlock_scenario["wrapping"],
                transition_source_state=LifecycleState.GRANTED,
                record_id=RECORD_ID,
                actor_id="dr-alice",
                correlation_id="corr-malformed-share",
                reason_code=ReasonCode.CARDIAC_ARREST,
                lifecycle_signing_key=unlock_scenario["lifecycle_priv"],
                pre_rewrap_key=pre_pub,
            )

    def test_redundant_shares_also_unlock(self, unlock_scenario):
        """All TOTAL_SHARES presented (more than THRESHOLD) still unlocks."""
        assert len(unlock_scenario["shares"]) == TOTAL_SHARES
        pre_priv, pre_pub = generate_pre_keypair()
        result = open_emergency_access(
            shares_presented=unlock_scenario["shares"],
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            actor_id="dr-alice",
            correlation_id="corr-002",
            reason_code=ReasonCode.STROKE,
            lifecycle_signing_key=unlock_scenario["lifecycle_priv"],
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
            actor_id="dr-alice",
            correlation_id="corr-003",
            reason_code=ReasonCode.MAJOR_TRAUMA,
            lifecycle_signing_key=unlock_scenario["lifecycle_priv"],
            pre_rewrap_key=pre_pub,
        )
        assert result.transition_event.from_state == LifecycleState.REVOKED


class TestEmergencyKeySplitCombineRoundTrip:
    def test_split_then_combine_recovers_key(self):
        key = generate_emergency_key()
        shares = split_emergency_key(key)
        assert len(shares) == TOTAL_SHARES
        recovered = combine_shares(shares[:THRESHOLD], k=THRESHOLD)
        assert recovered == key

    def test_different_threshold_pairs_all_recover_key(self):
        key = generate_emergency_key()
        shares = split_emergency_key(key)
        for i in range(TOTAL_SHARES):
            for j in range(i + 1, TOTAL_SHARES):
                pair = [shares[i], shares[j]]
                assert combine_shares(pair, k=THRESHOLD) == key


class TestTransitionEventShape:
    def test_result_transition_event_is_emergency_open(self, unlock_scenario):
        _, pre_pub = generate_pre_keypair()
        result = open_emergency_access(
            shares_presented=unlock_scenario["shares"][:THRESHOLD],
            dek_wrapping=unlock_scenario["wrapping"],
            transition_source_state=LifecycleState.GRANTED,
            record_id=RECORD_ID,
            actor_id="dr-alice",
            correlation_id="corr-004",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            lifecycle_signing_key=unlock_scenario["lifecycle_priv"],
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
