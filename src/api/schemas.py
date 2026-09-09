"""Pydantic schemas for the Hospital Node REST API (P4-1, C14).

These schemas define the wire-format request and response bodies for the
hospital node web service. No cryptographic computations take place here;
fields carry identifiers, structured parameters, or base64-encoded binary
payloads.
"""

from __future__ import annotations

from contracts.consent import ConsentGrant, ConsentRequest
from contracts.enums import LifecycleState, ReasonCode
from contracts.lifecycle import TransitionEvent
from contracts.messaging import EmergencyAssertion
from contracts.policy import PolicyTree
from pydantic import BaseModel, Field


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
    patient_public_key_pem: str | None = Field(
        default=None,
        description="PEM-encoded EC public key of patient to verify grant",
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


class CreateConsentRequestPayload(BaseModel):
    """Request body to issue a new ConsentRequest."""

    patient_id: str
    requester_id: str
    scope: list[str]
    purpose: str
    ttl_days: int = Field(default=7, gt=0, le=365)
    requester_signing_key_pem: str = Field(
        ...,
        description="PEM-encoded ECDSA private key of the requester",
    )


class SubmitConsentGrantPayload(BaseModel):
    """Request body submitting a patient-signed ConsentGrant."""

    grant: ConsentGrant
    patient_public_key_pem: str = Field(
        ...,
        description="PEM-encoded ECDSA public key of the patient",
    )


class RevokeConsentGrantPayload(BaseModel):
    """Request body revoking an existing ConsentGrant."""

    prior_grant: ConsentGrant
    patient_signing_key_pem: str = Field(
        ...,
        description="PEM-encoded ECDSA private key of the patient",
    )


class ConsentResponse(BaseModel):
    """Response returned by consent endpoints."""

    status: str
    grant: ConsentGrant | None = None
    request: ConsentRequest | None = None
    message: str


# --- Revocation by Key-Rotation Endpoint (P3-7, P3-12) ------------------------


class RevokeRecordRequest(BaseModel):
    """Request payload to cryptographically rotate a record's DEK."""

    actor_id: str = Field(
        ...,
        description="Party performing revocation (patient or home authority)",
    )
    actor_signing_key_pem: str = Field(
        ...,
        description="PEM-encoded ECDSA private key of actor",
    )
    old_dek_b64: str = Field(
        ...,
        description="Base64-encoded pre-revocation DEK",
    )
    new_clinical_policy: PolicyTree = Field(
        ...,
        description="New clinical policy branch (owner leaf added automatically)",
    )
    owner_authority_id: str = Field(
        ...,
        description="Authority owning the patient's owner namespace",
    )
    attribute_keyring: dict[str, str] = Field(
        ...,
        description="Keyring mapping 'auth_id:name:val' to base64 key bytes",
    )
    correlation_id: str | None = None
    reason_code: ReasonCode | None = None
    new_policy_id: str | None = None


class RevokeRecordResponse(BaseModel):
    """Result of cryptographic revocation by key rotation."""

    record_id: str
    new_generation: int
    new_policy_id: str
    transition_event: TransitionEvent
    message: str = "Record access revoked and DEK rotated successfully"


# --- Break-Glass Emergency Endpoint (P3-5, P3-10, P3-11) -----------------------


class BreakglassUnlockRequest(BaseModel):
    """Request payload for 2-of-3 threshold break-glass emergency unlock."""

    assertion: EmergencyAssertion = Field(
        ...,
        description="Signed EmergencyAssertion binding patient, clinician, facility",
    )
    clinician_certificate_pem: str = Field(
        ...,
        description="PEM-encoded X.509 certificate of attending clinician",
    )
    shares: list[tuple[int, str]] = Field(
        ...,
        description="List of (x_coordinate, hex_encoded_share) threshold shares",
    )
    pre_rewrap_key: int = Field(
        ...,
        description="Clinician's ElGamal PRE public key",
    )
    lifecycle_signing_key_pem: str = Field(
        ...,
        description="PEM-encoded ECDSA private key for signing TransitionEvent",
    )
    facility_ca_certificate_pem: str | None = Field(
        default=None,
        description="Facility CA certificate for chain validation",
    )
    trusted_root_certificate_pem: str | None = Field(
        default=None,
        description="Root anchor certificate for chain validation",
    )
    correlation_id: str | None = None
    baseline_wrapping_key_b64: str | None = Field(
        default=None,
        description="Base64-encoded baseline wrapping key (starts expiry session if present)",
    )
    emergency_duration_seconds: float | None = Field(
        default=None,
        description="Optional session duration override in seconds",
    )


class BreakglassUnlockResponse(BaseModel):
    """Result of break-glass unlock with re-wrapped DEK."""

    record_id: str
    rewrapped_dek_b64: str = Field(
        ...,
        description="Base64-encoded PRE-rewrapped DEK for emergency clinician",
    )
    transition_event: TransitionEvent
    correlation_id: str | None = None
    message: str = "Emergency access granted and DEK re-wrapped"


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
