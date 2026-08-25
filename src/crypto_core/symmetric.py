"""Symmetric cryptography: AES-256-GCM, HKDF-SHA256, SHA-256 (C1).

All primitive calls to ``cryptography.hazmat`` are contained within ``crypto_core``
per CONVENTIONS.md §2 rule 1.
"""

from __future__ import annotations

import os
import secrets

from contracts.base import GCM_NONCE_BYTES
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto_core.exceptions import InvalidTagError

DEFAULT_KEY_BYTES = 32  # 256 bits


def generate_key(num_bytes: int = DEFAULT_KEY_BYTES) -> bytes:
    """Generate cryptographically secure random key bytes.

    Args:
        num_bytes: Number of bytes to generate (default: 32 for 256-bit keys).

    Returns:
        Random key bytes.

    Security property:
        Entropy is derived from the system CSPRNG via ``secrets.token_bytes``
        (CONVENTIONS.md §2 rule 2).
    """
    return secrets.token_bytes(num_bytes)


def generate_nonce(num_bytes: int = GCM_NONCE_BYTES) -> bytes:
    """Generate a fresh GCM nonce.

    Args:
        num_bytes: Length of nonce (default: 12 bytes for 96-bit standard GCM).

    Returns:
        Random nonce bytes.

    Security property:
        Nonce uniqueness ensures GCM authentication and confidentiality guarantees
        are preserved (CONVENTIONS.md §2 rule 5).
    """
    return os.urandom(num_bytes)


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM with associated authenticated data.

    A fresh nonce is generated for every call and returned to the caller; the
    nonce is deliberately not accepted as a parameter, because AES-GCM nonce
    reuse under a single key is catastrophic (CONVENTIONS.md §2 rule 5). This
    closes off the one way a caller could reuse a nonce.

    Args:
        key: 32-byte AES key.
        plaintext: Plaintext bytes to encrypt.
        aad: Optional associated data to authenticate.

    Returns:
        A tuple of ``(ciphertext_with_tag, nonce)``.

    Raises:
        ValueError: If key length is invalid.

    Security property:
        Authenticated encryption (AEAD) ensures both confidentiality and
        ciphertext integrity. A fresh nonce is generated per encryption and can
        never be reused for a key.
    """
    if len(key) != DEFAULT_KEY_BYTES:
        raise ValueError(
            f"AES-256 key must be {DEFAULT_KEY_BYTES} bytes, got {len(key)}"
        )

    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext, nonce


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes | None = None,
) -> bytes:
    """Decrypt and verify ciphertext using AES-256-GCM.

    Args:
        key: 32-byte AES key.
        nonce: 12-byte GCM nonce.
        ciphertext: Encrypted ciphertext including authentication tag.
        aad: Optional associated data matching what was used during encryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If key or nonce length is invalid.
        InvalidTagError: If the ciphertext or tag is tampered with or key is wrong.

    Security property:
        Fails closed on any authentication tag mismatch (CONVENTIONS.md §2 rule 6).
    """
    if len(key) != DEFAULT_KEY_BYTES:
        raise ValueError(
            f"AES-256 key must be {DEFAULT_KEY_BYTES} bytes, got {len(key)}"
        )
    if len(nonce) != GCM_NONCE_BYTES:
        raise ValueError(f"GCM nonce must be {GCM_NONCE_BYTES} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise InvalidTagError("AES-GCM authentication tag verification failed") from exc


def hkdf_derive(
    ikm: bytes,
    salt: bytes | None,
    info: bytes,
    length: int = DEFAULT_KEY_BYTES,
) -> bytes:
    """Derive key material using HKDF-SHA256.

    Args:
        ikm: Input keying material.
        salt: Optional salt bytes (recommended for high entropy extraction).
        info: Context and application-specific info string/bytes.
        length: Output key length in bytes (default: 32).

    Returns:
        Derived key bytes.

    Security property:
        Context separation prevents cross-protocol key reuse and extracts uniform
        pseudorandom keys from input keying material.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def sha256_digest(data: bytes) -> bytes:
    """Compute the SHA-256 cryptographic digest of the input.

    Args:
        data: Input bytes.

    Returns:
        32-byte SHA-256 digest.

    Security property:
        Preimage resistance and collision resistance for hashing and audit logging.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
