"""Pydantic schemas for the Hospital Node REST API (P4-1, C14).

These schemas define the wire-format request and response bodies for the
hospital node web service. No cryptographic computations take place here;
fields carry identifiers, structured parameters, or base64-encoded binary
payloads.
"""

from __future__ import annotations

from breakglass.share_sealing import SealedShare
from contracts.clinical import ClinicalMetadata
from contracts.consent import ConsentGrant, ConsentRequest
from contracts.enums import LifecycleState
from contracts.lifecycle import TransitionEvent
from contracts.messaging import EmergencyAssertion
from contracts.policy import PolicyTree
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

# Longest break-glass window a caller may request (F6). The facility still
# caps it at its configured duration; this bound only rejects absurd values.
MAX_EMERGENCY_DURATION_SECONDS = 3 * 24 * 60 * 60


class HealthResponse(BaseModel):
    """Health check response for the hospital node service."""

    status: str = "ok"
    facility_id: str
    version: str = "1.0.0"


# --- Read Endpoint ------------------------------------------------------------


class ReadRecordRequest(BaseModel):
    """Request payload for reading a record under policy or consent."""

    requester_id: str = Field(..., description="Clinician or patient identity")
    holder_keyring: dict[str, str] = Field(
        default_factory=dict,
        description="Keyring mapping 'auth_id:name:val' to base64 key bytes",
    )
    grant: ConsentGrant | None = Field(
        default=None,
        description="Optional patient-signed ConsentGrant for consent gate",
    )
    patient_certificate_pem: str | None = Field(
        default=None,
        description=(
            "Patient certificate (PEM) from a configured facility CA; the grant "
            "is verified against its key, never a caller-supplied one (ADR-0064)"
        ),
    )
    correlation_id: str | None = Field(
        default=None,
        description="Audit correlation identifier",
    )


class ReadRecordResponse(BaseModel):
    """Decrypted plaintext record returned upon successful authorization."""

    record_id: str
    patient_id: str
    facility_id: str
    content_type: str
    plaintext_b64: str
    correlation_id: str | None = None


# --- Consent Endpoints --------------------------------------------------------


class SubmitConsentGrantPayload(BaseModel):
    """Request body submitting a patient-signed ConsentGrant."""

    grant: ConsentGrant
    patient_certificate_pem: str = Field(
        ...,
        description="Patient certificate (PEM) from a configured facility CA",
    )


class ConsentResponse(BaseModel):
    """Response returned by consent endpoints."""

    status: str
    grant: ConsentGrant | None = None
    request: ConsentRequest | None = None
    message: str


# --- Revocation by Key-Rotation Endpoint (P3-7, P3-12) ------------------------


class RevokeRecordRequest(BaseModel):
    """A patient's revocation of a record, signed by the patient (ADR-0080).

    The ``GRANTED -> REVOKED`` transition is signed with the patient's key in
    the custodian and verified here against the patient's certificate. The
    facility recovers the old DEK itself and re-keys the record (ADR-0069),
    so neither a private key nor a DEK crosses the wire; a caller still
    sending one gets a 422.
    """

    model_config = ConfigDict(extra="forbid")

    transition_event: TransitionEvent = Field(
        ...,
        description="GRANTED -> REVOKED, signed by the record's patient",
    )
    actor_certificate_pem: str = Field(
        ...,
        description="Patient certificate (PEM) from a configured facility CA",
    )
    new_clinical_policy: PolicyTree = Field(
        ...,
        description="New clinical policy branch (owner leaf added automatically)",
    )
    correlation_id: str | None = None


class RevokeRecordResponse(BaseModel):
    """Result of cryptographic revocation by key rotation."""

    record_id: str
    new_generation: int
    new_policy_id: str
    transition_event: TransitionEvent
    # False when the new emergency shares did not reach their holders: the
    # revocation holds, but break-glass on the record fails closed until it
    # is re-keyed (ADR-0080).
    breakglass_provisioned: bool = True
    message: str = "Record access revoked and DEK rotated successfully"


# --- Break-Glass Emergency Endpoint (P3-5, P3-10, P3-11) -----------------------


class BreakglassUnlockRequest(BaseModel):
    """Request payload for the 3-of-4 threshold break-glass unlock (ADR-0089).

    Trust anchors are facility configuration, never request data (F1). Extra
    fields are forbidden so a caller still sending its own root or CA gets a
    422 instead of having the field silently ignored.
    """

    model_config = ConfigDict(extra="forbid")
    sensitive_justification: str = Field(default="", max_length=2000)
    justification: str = Field(default="", max_length=2000)

    assertion: EmergencyAssertion = Field(
        ...,
        description="Signed EmergencyAssertion binding patient, clinician, facility",
    )
    clinician_certificate_pem: str = Field(
        ...,
        description="PEM-encoded X.509 certificate of attending clinician",
    )
    sealed_shares: list[SealedShare] = Field(
        ...,
        description=(
            "Threshold shares, each sealed to this facility's share key "
            "(ADR-0079); no share bytes cross the wire"
        ),
    )
    pre_rewrap_key: int = Field(
        ...,
        description="Clinician's ElGamal PRE public key",
    )
    transition_event: TransitionEvent | None = Field(
        default=None,
        description=(
            "The record's -> EMERGENCY_OPEN transition, signed with the "
            "clinician's own key inside the custodian (ADR-0068). Required to "
            "open; ignored when joining an open session. No private key is "
            "ever sent."
        ),
    )
    correlation_id: str | None = None
    emergency_duration_seconds: float | None = Field(
        default=None,
        gt=0,
        le=MAX_EMERGENCY_DURATION_SECONDS,
        description=(
            "Optional shorter session in seconds; never longer than the "
            "facility's configured duration (F6)"
        ),
    )
    join_only: bool = Field(
        default=False,
        description="Refuse (409) unless the record is already emergency_open",
    )


class BreakglassUnlockResponse(BaseModel):
    """Result of break-glass unlock with re-wrapped DEK."""

    record_id: str
    rewrapped_dek_b64: str = Field(
        ...,
        description="Base64-encoded PRE-rewrapped DEK for emergency clinician",
    )
    transition_event: TransitionEvent | None = Field(
        default=None,
        description="The signed transition into EMERGENCY_OPEN; None when joined",
    )
    joined: bool = Field(
        default=False,
        description="True when this joined an already open session (ADR-0057)",
    )
    correlation_id: str | None = None
    expires_at: AwareDatetime = Field(
        ...,
        description="When the session ends; the facility may shorten the request (F6)",
    )
    message: str = "Emergency access granted and DEK re-wrapped"


class LifecycleStateResponse(BaseModel):
    """A record's stored lifecycle state (the custodian signs transitions from it)."""

    record_id: str
    state: LifecycleState


# --- Search & Discovery Endpoints ---------------------------------------------


class DiscoveryResponse(BaseModel):
    """Result of federated patient record discovery (C13)."""

    patient_id: str
    record_ids: list[str]
    record_count: int


class SearchRecordsRequest(BaseModel):
    """Direct search token equality query."""

    coded_term_b64: str = Field(
        ...,
        description="Base64-encoded coded search token",
    )


class SearchRecordsResponse(BaseModel):
    """Matching record identifiers from searchable index."""

    record_ids: list[str]
    record_count: int


class EmergencySearchRequest(BaseModel):
    """Emergency-only plaintext search query."""

    search_term: str = Field(
        ...,
        description="Plaintext term to search in active emergency session",
    )
    requester_id: str = Field(
        ...,
        description="Clinician performing the search; recorded in the audit log (F8)",
    )
    correlation_id: str | None = None


# --- Record Ingest / Upload Endpoint (P3-14) ----------------------------------


class IngestRecordRequest(BaseModel):
    """Request payload to ingest an encrypted record into the store."""

    plaintext_b64: str = Field(
        ...,
        description="Base64-encoded record plaintext",
    )
    patient_id: str
    owner_authority_id: str
    clinical_policy: PolicyTree
    attribute_keyring: dict[str, str] = Field(
        ...,
        description="Keyring mapping 'auth_id:name:val' to base64 key",
    )
    search_terms: list[str] | None = None
    emergency_key_b64: str | None = None
    content_type: str = "application/json"
    record_id: str | None = None
    clinical: ClinicalMetadata = Field(default_factory=ClinicalMetadata)


class IngestRecordResponse(BaseModel):
    """Metadata of the ingested and encrypted record."""

    record_id: str
    policy_id: str
    wrapping_id: str
    lifecycle_state: LifecycleState
    search_terms_indexed: int
    message: str = "Record ingested, encrypted, and indexed successfully"


# --- Common Error Response ----------------------------------------------------


class ErrorResponse(BaseModel):
    """Standardized error structure for access denials and validation errors."""

    error: str
    detail: str
    denied_by: str | None = None
