"""Proxy Re-Encryption (owner module: ``pre``, C3).

Provides bidirectional ElGamal proxy re-encryption (ADR-0012, ADR-0076) and
the key encapsulation the break-glass gate uses to deliver an unwrapped DEK to
an emergency clinician.
"""

from __future__ import annotations

from pre.delivery import open_delivery_package
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
    "open_delivery_package",
    "reencrypt",
]
