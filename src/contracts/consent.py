"""Patient consent contracts (owner module: ``policy``/``lifecycle`` grant path).

Added by ADR-0014, which adopts a proper patient consent model: **signed, scoped,
expiring, request-then-approve**. The two schemas here are the two messages of
that flow -- a grantee's :class:`ConsentRequest` and the patient's signed
:class:`ConsentGrant` decision.

Critical boundary (ADR-0014): consent records the patient's signed *intent*; it
never *decides* decryption. Keys and the Shamir threshold gate decide access. A
``GRANTED`` consent tells the policy layer the patient approved a scope; the
policy layer, not this record, is what releases anything. These are wire/at-rest
value objects only -- the signing and verification happen in the owning module
through ``crypto_core`` (CONVENTIONS.md §2 rule 1).
"""

from __future__ import annotations

from uuid import UUID

from pydantic import AwareDatetime, field_validator, model_validator

from contracts.base import (
    MIN_ANTIREPLAY_NONCE_BYTES,
    B64Bytes,
    ContractModel,
    Identifier,
)
from contracts.enums import ConsentStatus


class ConsentRequest(ContractModel):
    """A grantee's signed request for access to a patient's records (ADR-0014).

    The "request" half of request-then-approve: a clinician (or facility) asks a
    patient for access to a *scoped* set of records for a stated purpose, and the
    request *expires* if not answered. Bound and signed so a patient approves a
    specific, attributable ask -- never an open-ended one. The request grants
    nothing; only a patient's :class:`ConsentGrant` does.
    """

    request_id: UUID  # one-time; consumed-id store rejects reuse (rule 9)
    patient_id: Identifier  # whose records are being asked for
    requester_id: Identifier  # the grantee asking; subject of the signature
    scope: tuple[Identifier, ...]  # record_ids requested; non-empty (fail closed)
    purpose: str  # why access is sought; surfaced to the patient
    requested_at: AwareDatetime
    expires_at: AwareDatetime  # the request lapses if unanswered
    nonce: B64Bytes
    signature: B64Bytes  # ECDSA over the other fields by the requester's key

    @model_validator(mode="after")
    def _expiry_after_request(self) -> "ConsentRequest":
        """A request that expires no later than it was made is invalid."""
        if self.expires_at <= self.requested_at:
            raise ValueError("expires_at must be after requested_at")
        return self

    @field_validator("scope")
    @classmethod
    def _scope_non_empty(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        """An empty scope is ambiguous between "nothing" and "everything".

        Security property: consent must name what it covers. A request with no
        records in scope is rejected at the boundary rather than left for the
        policy layer to interpret (fail closed).
        """
        if not v:
            raise ValueError("scope must name at least one record_id")
        return v

    @field_validator("purpose")
    @classmethod
    def _purpose_present(cls, v: str) -> str:
        """A consent ask with no stated purpose is not a meaningful request."""
        if not v.strip():
            raise ValueError("purpose must not be empty")
        return v

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
        """An unsigned request has no attributable requester."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v


class ConsentGrant(ContractModel):
    """A patient's signed decision on a consent request (ADR-0014).

    The "approve" half of request-then-approve, and the artifact of record for a
    consent decision. ``status`` carries the outcome; only ``GRANTED`` authorises
    access, and even then the policy layer -- not this record -- releases a key
    (ADR-0014 boundary). Signed by the *patient*, scoped to specific records, and
    expiring so consent is never a standing, unbounded permission.
    """

    grant_id: UUID  # one-time; consumed-id store rejects reuse (rule 9)
    request_id: UUID  # the ConsentRequest this answers
    patient_id: Identifier  # the consenting patient; subject of the signature
    grantee_id: Identifier  # who the decision concerns
    scope: tuple[Identifier, ...]  # record_ids decided on; non-empty (fail closed)
    status: ConsentStatus  # GRANTED authorises; all others fail closed
    decided_at: AwareDatetime
    expires_at: AwareDatetime  # consent is time-boxed, never standing
    nonce: B64Bytes
    signature: B64Bytes  # ECDSA over the other fields by the patient's key

    @model_validator(mode="after")
    def _expiry_after_decision(self) -> "ConsentGrant":
        """A decision that expires no later than it was made is invalid."""
        if self.expires_at <= self.decided_at:
            raise ValueError("expires_at must be after decided_at")
        return self

    @field_validator("scope")
    @classmethod
    def _scope_non_empty(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        """A decision must name the records it covers (fail closed).

        Security property: this holds for a denial too -- a ``DENIED`` grant
        denies a *specific* requested scope, not an unstated one.
        """
        if not v:
            raise ValueError("scope must name at least one record_id")
        return v

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
        """An unsigned consent decision is not the patient's provable intent."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v
