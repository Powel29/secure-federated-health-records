"""Tests for asymmetric cryptography in crypto_core (C1)."""

from __future__ import annotations

import pytest
from crypto_core.asymmetric import (
    generate_ec_keypair,
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
    sign,
    verify,
)
from crypto_core.exceptions import InvalidSignatureError, KeyFormatError


def test_ecdsa_sign_and_verify_round_trip() -> None:
    """Valid ECDSA signature should verify successfully."""
    sk, pk = generate_ec_keypair()
    message = b"Signed message payload for federation audit"

    signature = sign(sk, message)
    assert verify(pk, message, signature) is True


def test_ecdsa_tampered_message_rejected() -> None:
    """Tampering with signed message must raise InvalidSignatureError."""
    sk, pk = generate_ec_keypair()
    message = b"Original message"

    signature = sign(sk, message)
    with pytest.raises(InvalidSignatureError):
        verify(pk, message + b"tampered", signature)


def test_ecdsa_tampered_signature_rejected() -> None:
    """Tampering with signature bytes must raise InvalidSignatureError."""
    sk, pk = generate_ec_keypair()
    message = b"Important assertion"

    signature = sign(sk, message)
    tampered_sig = bytearray(signature)
    tampered_sig[-1] ^= 0xFF

    with pytest.raises(InvalidSignatureError):
        verify(pk, message, bytes(tampered_sig))


def test_ecdsa_wrong_public_key_rejected() -> None:
    """Verification with wrong public key must fail."""
    sk1, _ = generate_ec_keypair()
    _, pk2 = generate_ec_keypair()
    message = b"Signed message"

    signature = sign(sk1, message)
    with pytest.raises(InvalidSignatureError):
        verify(pk2, message, signature)


def test_pem_serialization_round_trip() -> None:
    """PEM export and import should preserve key validity."""
    sk, pk = generate_ec_keypair()
    message = b"Test message for PEM round trip"
    signature = sign(sk, message)

    sk_pem = private_key_to_pem(sk)
    pk_pem = public_key_to_pem(pk)

    reloaded_sk = private_key_from_pem(sk_pem)
    reloaded_pk = public_key_from_pem(pk_pem)

    assert verify(reloaded_pk, message, signature) is True
    new_signature = sign(reloaded_sk, message)
    assert verify(pk, message, new_signature) is True


def test_invalid_pem_raises_key_format_error() -> None:
    """Invalid PEM bytes must raise KeyFormatError."""
    with pytest.raises(KeyFormatError):
        private_key_from_pem(b"not-a-valid-pem")

    with pytest.raises(KeyFormatError):
        public_key_from_pem(b"not-a-valid-pem")
