"""Tests for record encryption and DEK wrapping (C8)."""

from __future__ import annotations

import pytest
from crypto_core.symmetric import generate_key
from records.exceptions import DecryptionError, UnwrappingError
from records.service import (
    decrypt_record,
    encrypt_record,
    rewrap_dek,
    unwrap_dek,
    wrap_dek,
)


def test_record_encrypt_decrypt_round_trip() -> None:
    """Encrypted record should be decrypted with the minted DEK."""
    plaintext = (
        b'{"diagnostic": "EHR test findings", '
        b'"vital_signs": {"hr": 72, "bp": "120/80"}}'
    )
    record, dek = encrypt_record(
        plaintext=plaintext,
        patient_id="pat-100",
        facility_id="fac-01",
        policy_id="pol-cardio",
    )

    assert record.patient_id == "pat-100"
    assert record.ciphertext != plaintext
    assert len(dek) == 32

    decrypted = decrypt_record(record, dek)
    assert decrypted == plaintext


def test_record_decrypt_with_wrong_dek_fails() -> None:
    """Decryption with wrong DEK must raise DecryptionError."""
    plaintext = b"Sample medical text"
    record, _ = encrypt_record(
        plaintext=plaintext,
        patient_id="pat-101",
        facility_id="fac-01",
        policy_id="pol-default",
    )
    wrong_dek = generate_key(32)

    with pytest.raises(DecryptionError):
        decrypt_record(record, wrong_dek)


def test_dek_wrap_unwrap_round_trip() -> None:
    """Wrapped DEK must unwrap cleanly under the correct wrapping key."""
    dek = generate_key(32)
    wrapping_key = generate_key(32)

    wrapping = wrap_dek(
        dek=dek,
        record_id="rec-001",
        wrapping_key=wrapping_key,
        wrapped_for="pol-root-secret",
    )

    assert wrapping.generation == 0
    assert wrapping.wrapped_dek != dek

    unwrapped_dek = unwrap_dek(wrapping, wrapping_key)
    assert unwrapped_dek == dek


def test_dek_unwrap_with_wrong_key_fails() -> None:
    """Unwrapping DEK with unauthorized key must raise UnwrappingError."""
    dek = generate_key(32)
    wrapping_key = generate_key(32)
    wrong_key = generate_key(32)

    wrapping = wrap_dek(
        dek=dek,
        record_id="rec-002",
        wrapping_key=wrapping_key,
        wrapped_for="pol-root-secret",
    )

    with pytest.raises(UnwrappingError):
        unwrap_dek(wrapping, wrong_key)


def test_dek_rewrap_increments_generation() -> None:
    """Re-wrapping DEK under a new key must increment the generation counter."""
    dek = generate_key(32)
    key_v0 = generate_key(32)
    key_v1 = generate_key(32)

    wrapping_v0 = wrap_dek(
        dek=dek,
        record_id="rec-003",
        wrapping_key=key_v0,
        wrapped_for="user-alice",
        generation=0,
    )

    wrapping_v1 = rewrap_dek(
        wrapping=wrapping_v0,
        old_wrapping_key=key_v0,
        new_wrapping_key=key_v1,
        new_wrapped_for="user-bob",
    )

    assert wrapping_v1.generation == 1
    assert wrapping_v1.wrapped_for == "user-bob"
    assert unwrap_dek(wrapping_v1, key_v1) == dek

    # Old key cannot unwrap new wrapping
    with pytest.raises(UnwrappingError):
        unwrap_dek(wrapping_v1, key_v0)
