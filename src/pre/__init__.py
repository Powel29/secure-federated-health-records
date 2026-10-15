"""Proxy Re-Encryption (owner module: ``pre``, C3).

Provides a hand-rolled ElGamal proxy re-encryption (ADR-0012) and the key
encapsulation break-glass delivers a DEK with. The scheme is bidirectional
and toy-sized, and break-glass uses only the encapsulation: the facility sees
the DEK it delivers (ADR-0071, review D11-a).
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
