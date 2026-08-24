"""Tests for symmetric cryptography in crypto_core (C1)."""

from __future__ import annotations

import pytest
from crypto_core.exceptions import InvalidTagError
from crypto_core.symmetric import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_key,
    generate_nonce,
    hkdf_derive,
    sha256_digest,
)


def test_aes_gcm_encrypt_decrypt_round_trip() -> None:
    """Authenticated AES-256-GCM round trip should restore exact plaintext."""
    key = generate_key(32)
    plaintext = b"Patient EHR Record Data: Diagnostic report 12345"
    aad = b"record_id:rec-001"

    ciphertext, nonce = aes_gcm_encrypt(key, plaintext, aad=aad)
    assert len(nonce) == 12
    assert ciphertext != plaintext

    decrypted = aes_gcm_decrypt(key, nonce, ciphertext, aad=aad)
    assert decrypted == plaintext


def test_aes_gcm_tampered_ciphertext_rejected() -> None:
    """Tampering with ciphertext must fail closed and raise InvalidTagError."""
    key = generate_key(32)
    plaintext = b"Confidential health info"
    aad = b"record_id:rec-002"

    ciphertext, nonce = aes_gcm_encrypt(key, plaintext, aad=aad)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01

    with pytest.raises(InvalidTagError):
        aes_gcm_decrypt(key, nonce, bytes(tampered), aad=aad)


def test_aes_gcm_tampered_aad_rejected() -> None:
    """Tampering with associated data must fail closed."""
    key = generate_key(32)
    plaintext = b"Confidential health info"

    ciphertext, nonce = aes_gcm_encrypt(key, plaintext, aad=b"correct-aad")

    with pytest.raises(InvalidTagError):
        aes_gcm_decrypt(key, nonce, ciphertext, aad=b"tampered-aad")


def test_aes_gcm_wrong_key_rejected() -> None:
    """Decrypting with wrong key must raise InvalidTagError."""
    key1 = generate_key(32)
    key2 = generate_key(32)
    plaintext = b"Sensitive test payload"

    ciphertext, nonce = aes_gcm_encrypt(key1, plaintext)

    with pytest.raises(InvalidTagError):
        aes_gcm_decrypt(key2, nonce, ciphertext)


def test_aes_gcm_fresh_nonce_per_encryption() -> None:
    """Two successive encryptions must generate distinct nonces."""
    key = generate_key(32)
    plaintext = b"Identical plaintext"

    _, nonce1 = aes_gcm_encrypt(key, plaintext)
    _, nonce2 = aes_gcm_encrypt(key, plaintext)

    assert nonce1 != nonce2


def test_hkdf_deterministic_and_context_separated() -> None:
    """HKDF-SHA256 must be deterministic for same context and separated for distinct."""
    ikm = generate_key(32)
    salt = generate_nonce(16)

    key1 = hkdf_derive(ikm, salt, info=b"context-A")
    key2 = hkdf_derive(ikm, salt, info=b"context-A")
    key3 = hkdf_derive(ikm, salt, info=b"context-B")

    assert key1 == key2
    assert key1 != key3
    assert len(key1) == 32


def test_sha256_digest() -> None:
    """SHA-256 digest should match known vector."""
    message = b"hello world"
    expected = bytes.fromhex(
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )
    assert sha256_digest(message) == expected
