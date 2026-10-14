"""Record and DEK-wrapping contracts (owner module: ``records``, C8)."""

from __future__ import annotations

from pydantic import AwareDatetime, Field, field_validator

from contracts.base import (
    GCM_NONCE_BYTES,
    B64Bytes,
    ContractModel,
    Identifier,
)
from contracts.clinical import ClinicalMetadata


class Record(ContractModel):
    """An encrypted health record. One DEK per record, AES-256-GCM (§2 C8).

    The contract carries only ciphertext -- plaintext contents never appear in a
    contract, on the wire, or in a log (CONVENTIONS.md §2 rule 3). Decryption
    requires the DEK, which is recovered from a :class:`DEKWrapping` via the
    policy engine.
    """

    record_id: Identifier
    patient_id: Identifier
    facility_id: Identifier  # the facility that owns/holds this record
    policy_id: Identifier  # access policy governing decryption (see PolicyTree)
    content_type: str  # media type of the *plaintext*, e.g. "application/json"
    ciphertext: B64Bytes  # AES-256-GCM output, authentication tag included
    nonce: B64Bytes  # per-encryption GCM nonce; never reused for a key (rule 5)
    aad: B64Bytes | None = None  # optional associated data bound by GCM
    created_at: AwareDatetime
    clinical: ClinicalMetadata = Field(default_factory=ClinicalMetadata)

    @field_validator("nonce")
    @classmethod
    def _nonce_is_gcm_sized(cls, v: bytes) -> bytes:
        """Reject any nonce that is not the 96-bit AES-GCM nonce (fail closed).

        Security property: a short or malformed nonce is a nonce-misuse footgun;
        the contract refuses it at the boundary rather than trusting the caller.
        """
        if len(v) != GCM_NONCE_BYTES:
            raise ValueError(f"GCM nonce must be {GCM_NONCE_BYTES} bytes, got {len(v)}")
        return v


class DEKWrapping(ContractModel):
    """A record's data-encryption key, sealed under a wrapping key (§2 C8).

    Envelope encryption: the DEK is wrapped once per authorised party (a policy
    root secret, or a specific party such as the break-glass emergency key).
    ``generation`` increments on re-wrap so rotation is auditable
    (ARCHITECTURE.md §2 C8, "re-wrap on rotation").
    """

    wrapping_id: Identifier
    record_id: Identifier  # the record whose DEK this wraps
    wrapped_for: Identifier  # policy_id or party id whose key unwraps this
    wrapped_dek: B64Bytes  # the sealed DEK
    nonce: B64Bytes  # GCM nonce used to wrap the DEK
    generation: int  # rotation counter; re-wrap produces a higher generation
    created_at: AwareDatetime

    @field_validator("generation")
    @classmethod
    def _generation_non_negative(cls, v: int) -> int:
        """Generation counts from 0 and only ever increases."""
        if v < 0:
            raise ValueError("generation must be >= 0")
        return v

    @field_validator("nonce")
    @classmethod
    def _nonce_is_gcm_sized(cls, v: bytes) -> bytes:
        """Reject a wrap nonce that is not the 96-bit AES-GCM nonce."""
        if len(v) != GCM_NONCE_BYTES:
            raise ValueError(f"GCM nonce must be {GCM_NONCE_BYTES} bytes, got {len(v)}")
        return v
