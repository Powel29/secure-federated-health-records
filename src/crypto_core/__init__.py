"""Core cryptographic primitives (owner module: ``crypto_core``, C1).

Provides AES-256-GCM, HKDF-SHA256, SHA-256 digests, and ECDSA P-256 sign/verify.
Per CONVENTIONS.md §2 rule 1, all other modules must import primitive operations
from this package rather than directly importing ``cryptography.hazmat``.
"""

from __future__ import annotations

from crypto_core.asymmetric import (
    generate_ec_keypair,
    private_key_from_pem,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
    sign,
    verify,
)
from crypto_core.exceptions import (
    CertificateExpiredError,
    CryptoError,
    InvalidSignatureError,
    InvalidTagError,
    KeyFormatError,
)
from crypto_core.symmetric import (
    DEFAULT_KEY_BYTES,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_key,
    generate_nonce,
    hkdf_derive,
    sha256_digest,
)
from crypto_core.x509_certs import (
    build_certificate,
    build_self_signed_tls_cert,
    certificate_from_pem,
    certificate_public_key,
    certificate_role,
    certificate_to_pem,
    check_certificate_validity_window,
    is_ca_certificate,
    verify_certificate_signature,
)

__all__ = [
    "DEFAULT_KEY_BYTES",
    "CertificateExpiredError",
    "CryptoError",
    "InvalidSignatureError",
    "InvalidTagError",
    "KeyFormatError",
    "aes_gcm_decrypt",
    "aes_gcm_encrypt",
    "build_certificate",
    "build_self_signed_tls_cert",
    "certificate_from_pem",
    "certificate_public_key",
    "certificate_role",
    "certificate_to_pem",
    "check_certificate_validity_window",
    "generate_ec_keypair",
    "generate_key",
    "generate_nonce",
    "hkdf_derive",
    "is_ca_certificate",
    "private_key_from_pem",
    "private_key_to_pem",
    "public_key_from_pem",
    "public_key_to_pem",
    "sha256_digest",
    "sign",
    "verify",
    "verify_certificate_signature",
]
