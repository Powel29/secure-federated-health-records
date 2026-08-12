"""Audit-log contract (owner module: ``audit``, C10)."""

from __future__ import annotations

from typing import Any

from pydantic import AwareDatetime, field_validator

from contracts.base import (
    SHA256_DIGEST_BYTES,
    B64Bytes,
    ContractModel,
    Identifier,
)


class AuditEntry(ContractModel):
    """One link in the hash-chained, signed audit log (§2 C10).

    The chain is ``h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)``. This
    contract holds a computed link; the hashing and signing happen in the
    ``audit`` module through ``crypto_core``. Full-chain verification recomputes
    each ``entry_hash`` from the previous one and re-checks every signature.

    ``event_data`` carries identifiers, hashes, and metadata only -- never key
    material, DEKs, shares, or plaintext record contents (CONVENTIONS.md §2
    rule 3).
    """

    seq: int  # position in the chain, monotonic from 0
    prev_hash: B64Bytes  # h_{i-1}; the genesis entry uses 32 zero bytes
    entry_hash: B64Bytes  # h_i
    event_type: str  # e.g. "transition", "breakglass_share_release"
    event_data: dict[str, Any]  # metadata only; see rule 3 above
    actor_id: Identifier
    timestamp: AwareDatetime
    signature: B64Bytes  # ECDSA over this entry by the audit service key

    @field_validator("seq")
    @classmethod
    def _seq_non_negative(cls, v: int) -> int:
        """Chain positions start at 0 and never go backwards."""
        if v < 0:
            raise ValueError("seq must be >= 0")
        return v

    @field_validator("prev_hash", "entry_hash")
    @classmethod
    def _digest_is_sha256(cls, v: bytes) -> bytes:
        """A chain hash must be exactly one SHA-256 digest (fail closed).

        Security property: a wrong-length hash cannot be a valid chain link, so
        it is rejected before it can be accepted into the log.
        """
        if len(v) != SHA256_DIGEST_BYTES:
            raise ValueError(f"hash must be {SHA256_DIGEST_BYTES} bytes, got {len(v)}")
        return v

    @field_validator("signature")
    @classmethod
    def _signature_present(cls, v: bytes) -> bytes:
        """An unsigned audit entry is not evidence of anything."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v
