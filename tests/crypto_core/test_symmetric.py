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


def test_aes_256_gcm_known_answer_vector() -> None:
    """AES-256-GCM matches a published known-answer vector (P1-1 exit criterion).

    McGrew & Viega GCM Test Case 16 (AES-256 with AAD), the same vector set NIST
    references. ``aes_gcm_encrypt`` generates its own nonce and so cannot be
    driven from a fixed IV; the deterministic direction is decryption, so the
    KAT verifies ``aes_gcm_decrypt`` reproduces the reference plaintext from the
    reference key/nonce/ciphertext/tag/AAD.
    """
    key = bytes.fromhex(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    )
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    ciphertext = bytes.fromhex(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
    )
    tag = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")
    expected_plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )

    recovered = aes_gcm_decrypt(key, nonce, ciphertext + tag, aad)
    assert recovered == expected_plaintext


def test_hkdf_sha256_known_answer_vector() -> None:
    """HKDF-SHA256 matches RFC 5869 Test Case 1 (P1-1 exit criterion)."""
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )

    assert hkdf_derive(ikm, salt, info, length=42) == expected_okm
