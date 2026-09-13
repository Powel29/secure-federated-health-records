"""Tests for ``pre.delivery.open_delivery_package`` -- the inverse of gate step 4."""

from __future__ import annotations

import pytest
from breakglass.emergency_key import generate_emergency_key, split_emergency_key
from breakglass.gate import open_emergency_access
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import generate_ec_keypair, generate_key
from crypto_core.exceptions import InvalidTagError
from pre import generate_keypair, open_delivery_package
from pre.exceptions import PREDecryptionError
from records.service import wrap_dek


def _delivery_package(record_id: str, pre_pub: int) -> tuple[bytes, bytes]:
    """Run the real gate so the package is exactly what a clinician receives."""
    em_key = generate_emergency_key()
    shares = split_emergency_key(em_key)
    dek = generate_key()
    wrapping = wrap_dek(
        dek=dek, record_id=record_id, wrapping_key=em_key, wrapped_for="emergency"
    )
    life_priv, _ = generate_ec_keypair()
    result = open_emergency_access(
        shares_presented=shares[:2],
        dek_wrapping=wrapping,
        transition_source_state=LifecycleState.GRANTED,
        record_id=record_id,
        actor_id="doc-301",
        correlation_id="corr-1",
        reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
        lifecycle_signing_key=life_priv,
        pre_rewrap_key=pre_pub,
    )
    return result.rewrapped_dek, dek


def test_round_trip_recovers_the_dek() -> None:
    pre_priv, pre_pub = generate_keypair()
    package, dek = _delivery_package("rec-001", pre_pub)
    assert (
        open_delivery_package(package, pre_private_key=pre_priv, record_id="rec-001")
        == dek
    )


def test_wrong_pre_key_does_not_open_the_package() -> None:
    _, pre_pub = generate_keypair()
    other_priv, _ = generate_keypair()
    package, _ = _delivery_package("rec-001", pre_pub)
    with pytest.raises(InvalidTagError):
        open_delivery_package(package, pre_private_key=other_priv, record_id="rec-001")


def test_package_is_bound_to_its_record_id() -> None:
    pre_priv, pre_pub = generate_keypair()
    package, _ = _delivery_package("rec-001", pre_pub)
    with pytest.raises(InvalidTagError):
        open_delivery_package(package, pre_private_key=pre_priv, record_id="rec-002")


def test_truncated_package_is_rejected_before_any_decryption() -> None:
    pre_priv, _ = generate_keypair()
    with pytest.raises(PREDecryptionError):
        open_delivery_package(
            b"\x00" * 40, pre_private_key=pre_priv, record_id="rec-001"
        )
