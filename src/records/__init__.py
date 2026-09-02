"""Record encryption, envelope key management, and ingest (``records``, C8).

Provides per-record DEK minting, AES-256-GCM record encryption, DEK wrapping,
key rotation re-wrapping, and the full record upload pipeline (P3-14).
"""

from __future__ import annotations

from records.exceptions import DecryptionError, RecordError, UnwrappingError
from records.ingest import IngestResult, ingest_record
from records.service import (
    decrypt_record,
    encrypt_record,
    rewrap_dek,
    unwrap_dek,
    wrap_dek,
)

__all__ = [
    "DecryptionError",
    "IngestResult",
    "RecordError",
    "UnwrappingError",
    "decrypt_record",
    "encrypt_record",
    "ingest_record",
    "rewrap_dek",
    "unwrap_dek",
    "wrap_dek",
]
