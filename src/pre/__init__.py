"""Proxy Re-Encryption (owner module: ``pre``, C3).

Provides unidirectional ElGamal proxy re-encryption (ADR-0012) for re-wrapping
ciphertexts to emergency clinicians without plaintext exposure.
"""

from __future__ import annotations

from pre.elgamal import (
    decapsulate_key,
    decrypt_point,
    encapsulate_key,
    encrypt_point,
    generate_keypair,
    generate_rekey,
    reencrypt,
)
from pre.exceptions import PREDecryptionError, PREError, PREKeyError

__all__ = [
    "PREDecryptionError",
    "PREError",
    "PREKeyError",
    "decapsulate_key",
    "decrypt_point",
    "encapsulate_key",
    "encrypt_point",
    "generate_keypair",
    "generate_rekey",
    "reencrypt",
]
