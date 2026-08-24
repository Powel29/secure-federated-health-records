"""Record encryption and envelope key management (owner module: ``records``, C8).

Provides per-record DEK minting, AES-256-GCM record encryption, DEK wrapping,
and key rotation re-wrapping.
"""

from __future__ import annotations

from records.exceptions import DecryptionError, RecordError, UnwrappingError
from records.service import (
    decrypt_record,
    encrypt_record,
    rewrap_dek,
    unwrap_dek,
    wrap_dek,
)

__all__ = [
    "DecryptionError",
    "RecordError",
    "UnwrappingError",
    "decrypt_record",
    "encrypt_record",
    "rewrap_dek",
    "unwrap_dek",
    "wrap_dek",
]
