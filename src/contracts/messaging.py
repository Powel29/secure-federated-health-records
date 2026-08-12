"""Security-envelope contracts added by the external security review (§8).

``EmergencyAssertion`` is the signed trigger for break-glass; ``RequestEnvelope``
is the signed, one-time-id wrapper around every inter-service request. Both were
added after the review (ARCHITECTURE.md §8) and are the two schemas beyond the
original seven named in CONVENTIONS.md §3 -- see the T02 freeze note in
``__init__``.
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
from contracts.enums import ReasonCode


class EmergencyAssertion(ContractModel):
    """The signed structure that opens break-glass for one patient (§8).

    Every field except the signature is *bound*: the assertion opens exactly this
    patient, at exactly this facility, declared by exactly this clinician. This
    contract is the wire/at-rest shape only. The validation sequence in
    ARCHITECTURE.md §8 -- signature verifies against a currently-valid clinician
    certificate, ``clinician_id`` matches the certificate subject, ``facility_id``
    matches the receiving node, ``expires_at`` is in the future, ``assertion_id``
    is unconsumed -- is implemented in the emergency-assertion protocol (T48),
    not here. A structural failure below means the assertion never reaches that
    protocol.
    """

    assertion_id: UUID  # one-time; consumed on use, replay rejected
    patient_id: Identifier  # bound: opens this patient only
    clinician_id: Identifier  # bound: subject of the presenting certificate
    facility_id: Identifier  # bound: where the emergency is declared
    reason_code: ReasonCode  # constrained enum, never free text
    issued_at: AwareDatetime
    expires_at: AwareDatetime  # short-lived; not a standing permission
    nonce: B64Bytes
    signature: B64Bytes  # ECDSA by the clinician's certificate key

    @model_validator(mode="after")
    def _expiry_after_issue(self) -> "EmergencyAssertion":
        """An assertion that expires no later than it was issued is invalid."""
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    @field_validator("nonce")
    @classmethod
    def _nonce_long_enough(cls, v: bytes) -> bytes:
        """Reject an anti-replay nonce shorter than 128 bits."""
        if len(v) < MIN_ANTIREPLAY_NONCE_BYTES:
            raise ValueError(
                f"nonce must be >= {MIN_ANTIREPLAY_NONCE_BYTES} bytes, got {len(v)}"
            )
        return v

    @field_validator("signature")
    @classmethod
    def _signature_present(cls, v: bytes) -> bytes:
        """An unsigned assertion is exactly the undefined trigger §8 removed."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v


class RequestEnvelope(ContractModel):
    """Signed, one-time wrapper around an inter-service request (§8).

    Realises two §8 controls at once: service identity (every inter-service
    request is signed by the caller and verified by the callee) and replay
    protection (a one-time ``request_id`` the callee's consumed-id store rejects
    on reuse; CONVENTIONS.md §2 rule 9). ``body`` is the opaque canonical
    serialization of the wrapped message -- the envelope neither inspects nor
    decrypts it. ``recipient_id`` binds the envelope to its destination so one
    captured at one service cannot be presented to another.
    """

    request_id: UUID  # one-time; consumed-id store rejects reuse
    caller_id: Identifier  # calling service identity
    recipient_id: Identifier  # intended callee; envelope is bound to it
    operation: str  # logical operation name, for routing and audit correlation
    body: B64Bytes  # opaque canonical serialization of the wrapped payload
    issued_at: AwareDatetime
    nonce: B64Bytes
    signature: B64Bytes  # ECDSA over the other fields by the caller service key

    @field_validator("nonce")
    @classmethod
    def _nonce_long_enough(cls, v: bytes) -> bytes:
        """Reject an anti-replay nonce shorter than 128 bits."""
        if len(v) < MIN_ANTIREPLAY_NONCE_BYTES:
            raise ValueError(
                f"nonce must be >= {MIN_ANTIREPLAY_NONCE_BYTES} bytes, got {len(v)}"
            )
        return v

    @field_validator("signature")
    @classmethod
    def _signature_present(cls, v: bytes) -> bytes:
        """An unsigned request has no verifiable caller identity."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v
