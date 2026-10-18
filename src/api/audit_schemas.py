"""Pydantic schemas for the standalone Audit Service (P4-2, C14/C10).

Wire-format request and response bodies only. No cryptographic computation
happens here (CONVENTIONS.md §2 rule 10) -- ``audit_service.py`` orchestrates
calls into ``audit.chain`` / ``audit.share_custody``, which is where every
hash and signature is actually computed.
"""

from __future__ import annotations

from typing import Any

from breakglass.share_sealing import SealedShare, ShareKeyStatement
from contracts import AuditEntry, EmergencyAssertion
from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Health check response for the audit service."""

    status: str = "ok"
    actor_id: str
    chain_head_seq: int | None = None


class PublicKeyResponse(BaseModel):
    """This service's ECDSA-P256 public key, for chain verification elsewhere."""

    public_key_pem: str


class ChainHeadResponse(BaseModel):
    """The chain's current head entry, or ``None`` before genesis exists."""

    head: AuditEntry | None


class ChainVerifyResponse(BaseModel):
    """Result of re-verifying the whole persisted chain."""

    verified: bool
    head_seq: int | None = None


class AppendEntryRequest(BaseModel):
    """Ask the audit service to sign and append one entry on this caller's behalf.

    ``event_data`` must carry identifiers and hashes only -- never key
    material, shares, DEKs, or plaintext (CONVENTIONS.md §2 rule 3). This
    endpoint does not and cannot enforce that beyond documenting it, exactly
    like ``audit.share_custody.release_share_after_commit`` itself.
    """

    event_type: str
    event_data: dict[str, Any] = Field(default_factory=dict)
    actor_id: str
    correlation_id: str


class AppendEntryResponse(BaseModel):
    """The newly persisted, signed entry -- the new chain head."""

    entry: AuditEntry


class RegisterShareRequest(BaseModel):
    """Hand this service custody of one break-glass share (share 3).

    Normally called once per record at seed/ingest time by whoever performed
    the 2-of-3 split (``breakglass.emergency_key.split_emergency_key``), to
    give the audit service its own copy out of band.
    """

    share_key: str = Field(..., description="Usually the record_id this share protects")
    # Sealed to this service's share key (ADR-0079): no share bytes on the wire.
    sealed_share: SealedShare


class RegisterShareResponse(BaseModel):
    status: str = "registered"
    share_key: str


class ReplaceShareRequest(BaseModel):
    """Replace a held share with the next generation's (ADR-0069).

    Sent by the facility that ran a record's forced rotation at expiry.
    """

    sealed_share: SealedShare
    generation: int = Field(..., ge=1)


class ReleaseShareRequest(BaseModel):
    """Request the audit service's share, gated on a durable log commit first.

    ARCHITECTURE.md §5 step 3: "the audit service computes and commits
    ``h_i`` first, and only then returns its share along with the new chain
    head. If the log write fails, no share is returned and break-glass fails
    closed." This is that request, made over the network so the precondition
    is enforced by a genuinely separate process rather than an in-process
    function call (ARCHITECTURE.md §7).

    Before any of that, the audit service validates the clinician's signed
    ``EmergencyAssertion`` itself (ADR-0067, D1-a): a share holder that
    releases without checking anything is a single party able to open a
    record together with share 1. ``justification`` texts are only checked
    against the assertion's signed digest, which binds the record; they are
    never logged.
    """

    model_config = ConfigDict(extra="forbid")

    share_key: str
    assertion: EmergencyAssertion
    clinician_certificate_pem: str
    justification: str = Field(default="", max_length=2000)
    sensitive_justification: str = Field(default="", max_length=2000)
    event_type: str = "breakglass_share_release"
    event_data: dict[str, Any] = Field(default_factory=dict)
    actor_id: str
    correlation_id: str
    # The facility whose gate will combine the shares: share 3 is sealed to
    # its key, so the caller forwarding it never sees it (ADR-0079).
    recipient: ShareKeyStatement


class ReleaseShareResponse(BaseModel):
    """The released share and the audit entry committed immediately before it."""

    sealed_share: SealedShare
    entry: AuditEntry


class ErrorResponse(BaseModel):
    detail: str
