"""Lifecycle transition contract (owner module: ``lifecycle``, C9)."""

from __future__ import annotations

from uuid import UUID

from pydantic import AwareDatetime, field_validator

from contracts.base import (
    MIN_ANTIREPLAY_NONCE_BYTES,
    B64Bytes,
    ContractModel,
    Identifier,
)
from contracts.enums import LifecycleState, ReasonCode


class TransitionEvent(ContractModel):
    """A signed record of one key-lifecycle state transition (§2 C9).

    Carries a one-time ``event_id`` so a captured transition cannot be replayed
    (ARCHITECTURE.md §8 replay protection; CONVENTIONS.md §2 rule 9). The
    signature is produced and verified by the ``lifecycle`` module through
    ``crypto_core``; the contract only transports it.

    Note: ``expiry_ts`` is intentionally *not* a field in this initial freeze.
    CONVENTIONS.md §4 uses "add expiry_ts to TransitionEvent" as its worked
    example of a future ``contract:`` PR, so adding it is a ratified change, not
    part of v1. Emergency-open time-boxing is carried today by the emergency key
    lifetime and EmergencyAssertion.expires_at.
    """

    event_id: UUID  # one-time; consumed-id store rejects reuse
    record_id: Identifier  # subject of the transition
    from_state: LifecycleState
    to_state: LifecycleState
    actor_id: Identifier  # who caused the transition
    reason_code: ReasonCode | None = None  # context; required for some transitions
    issued_at: AwareDatetime
    nonce: B64Bytes
    signature: B64Bytes  # ECDSA over the canonical serialization of the fields

    @field_validator("nonce")
    @classmethod
    def _nonce_long_enough(cls, v: bytes) -> bytes:
        """Reject an anti-replay nonce shorter than 128 bits (fail closed)."""
        if len(v) < MIN_ANTIREPLAY_NONCE_BYTES:
            raise ValueError(
                f"nonce must be >= {MIN_ANTIREPLAY_NONCE_BYTES} bytes, got {len(v)}"
            )
        return v

    @field_validator("signature")
    @classmethod
    def _signature_present(cls, v: bytes) -> bytes:
        """A transition event is meaningless unsigned."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v
