"""Pydantic schemas for the Key Custodian Service (ADR-0043, C14).

Wire-format request and response bodies only. No cryptographic computation
happens here (CONVENTIONS.md §2 rule 10) -- ``custodian_service.py``
orchestrates calls into ``consent.service``, ``breakglass.assertion``,
``pre.delivery`` and ``records.service``, which is where every signature and
cipher call actually happens.

The one place private material crosses the wire is the bootstrap deposit
(:class:`DepositMaterialRequest`): the seed step hands each synthetic
persona's key material to the custodian once, the same way it hands the
audit service its share 3 (``POST /breakglass/shares``). Nothing below ever
*returns* a private key.
"""

from __future__ import annotations

import datetime
from typing import Any, Literal

from contracts import AttributeCredential, TransitionEvent
from contracts.consent import ConsentGrant, ConsentRequest
from contracts.enums import ReasonCode
from contracts.policy import PolicyTree
from pydantic import BaseModel, Field

_THREE_DAYS_SECONDS = 3 * 24 * 60 * 60

SubjectKind = Literal["patient", "clinician"]


class HealthResponse(BaseModel):
    status: str = "ok"
    subjects: int = 0


# --- Bootstrap: trust anchors and per-subject material ------------------------


class TrustMaterialRequest(BaseModel):
    """Public trust material every break-glass call must present (P4-1 contract).

    ``facility_ca_certificate_pems`` maps ``facility_id`` to that facility's CA
    certificate; ``root_certificate_pem`` is the federation anchor. Both are
    public -- the same PEMs ``deploy/pki/federation.json`` carries.
    """

    root_certificate_pem: str
    facility_ca_certificate_pems: dict[str, str] = Field(default_factory=dict)
    # The audit service's public key, so the custodian can check that the
    # entry returned with a released share is really the audit service's
    # (review F31). Bootstrap reads it from the audit service directly.
    audit_public_key_pem: str | None = None


class DepositMaterialRequest(BaseModel):
    """Hand the custodian one subject's private material (bootstrap only).

    A clinician deposits their certificate key, certificate, PRE keypair and
    authority-issued credentials; a patient deposits their signing key and
    ``owner:<patient_id>`` credential (ADR-0016). Depositing again for the
    same ``subject_id`` replaces the previous material.
    """

    kind: SubjectKind
    signing_key_pem: str = Field(..., description="ECDSA-P256 private key PEM")
    display_name: str = ""
    facility_id: str | None = None
    certificate_pem: str | None = None
    pre_private_key: int | None = None
    pre_public_key: int | None = None
    credentials: list[AttributeCredential] = Field(default_factory=list)


class DepositMaterialResponse(BaseModel):
    status: str = "deposited"
    subject_id: str
    credentials: int


class DepositShareRequest(BaseModel):
    """Deposit the attending-clinician break-glass share (share 1) for a record.

    The 2-of-3 split happens at seed/ingest time (``breakglass.emergency_key``);
    share 3 goes to the audit service, share 1 to clinician custody -- which,
    in this deployment, is the custodian acting as every clinician's key
    agent (ADR-0043). Share 2 (home authority) is not deposited anywhere: the
    demo threshold is satisfied by shares 1 + 3, exactly as ``deploy/run_scenario``
    and ``demo/driver`` present it.
    """

    x: int
    share_hex: str


class DepositShareResponse(BaseModel):
    status: str = "deposited"
    record_id: str
    x: int


# --- Public read-back --------------------------------------------------------


class CredentialSummary(BaseModel):
    serial: str
    issuer_id: str
    name: str
    value: str
    valid_until: datetime.datetime
    status: str


class SubjectSummary(BaseModel):
    """What a portal may learn about a subject: public identity, never a key."""

    subject_id: str
    kind: SubjectKind
    display_name: str
    facility_id: str | None
    public_key_pem: str
    certificate_pem: str | None
    pre_public_key: int | None
    credentials: list[CredentialSummary]


class PublicKeyResponse(BaseModel):
    subject_id: str
    public_key_pem: str


# --- Consent (ADR-0014 request-then-approve; ADR-0031 gate) ------------------


class SignConsentRequestPayload(BaseModel):
    """A clinician asks the custodian to sign a ``ConsentRequest`` for them."""

    patient_id: str
    scope: list[str] = Field(..., min_length=1)
    purpose: str
    ttl_days: int = Field(default=7, gt=0, le=365)


class SignConsentRequestResponse(BaseModel):
    request: ConsentRequest


class DecideConsentPayload(BaseModel):
    """A patient asks the custodian to sign their decision on a request."""

    request: ConsentRequest
    status: Literal["granted", "denied"]
    ttl_days: int = Field(default=7, gt=0, le=365)


class RevokeConsentPayload(BaseModel):
    """A patient asks the custodian to sign a revocation of a prior grant."""

    prior_grant: ConsentGrant


class SignedGrantResponse(BaseModel):
    grant: ConsentGrant
    patient_public_key_pem: str


# --- Key-bearing federation calls performed on the subject's behalf ----------


class ReadRecordPayload(BaseModel):
    """Read a record at ``facility_id`` with this subject's attribute keys.

    With ``grant`` present the read goes through the consent gate
    (``consent.service.read_record_under_consent``); without it, straight
    through the policy tree -- which is how a patient reads their own record
    via the ``owner:<patient_id>`` leaf (ADR-0016).
    """

    record_id: str
    facility_id: str
    grant: ConsentGrant | None = None
    correlation_id: str | None = None


class ReadRecordResult(BaseModel):
    record_id: str
    patient_id: str
    facility_id: str
    content_type: str
    plaintext_b64: str
    access_via: str
    correlation_id: str | None
    attributes_presented: list[str]


class BreakglassPayload(BaseModel):
    """Declare break-glass for ``patient_id`` on ``record_id`` (ARCHITECTURE §5/§8).

    ``patient_id`` is the identifier resolved by the clinician portal's
    name + DOB lookup (ADR-0033, step 0); the custodian binds it into the
    signed ``EmergencyAssertion`` and never second-guesses it.
    """

    patient_id: str
    record_id: str
    reason_code: ReasonCode
    facility_id: str | None = Field(
        default=None,
        description="Where the emergency is declared; defaults to the clinician's",
    )
    correlation_id: str | None = None
    # Both bounded at 3 days (F6): the facility rejects a longer assertion and
    # caps the window at its configured duration anyway.
    assertion_ttl_seconds: int = Field(default=120, gt=0, le=_THREE_DAYS_SECONDS)
    emergency_duration_seconds: float | None = Field(
        default=None, gt=0, le=_THREE_DAYS_SECONDS
    )


class SharePresented(BaseModel):
    holder: str
    x: int
    audit_entry_seq: int | None = None


class BreakglassResult(BaseModel):
    record_id: str
    patient_id: str
    facility_id: str
    clinician_id: str
    correlation_id: str
    assertion_id: str
    assertion_expires_at: datetime.datetime
    shares_presented: list[SharePresented]
    transition_event: TransitionEvent
    opened_at: datetime.datetime
    expires_at: datetime.datetime | None
    content_type: str | None
    plaintext_b64: str | None
    detail: str = "Emergency access granted; DEK recovered through PRE delivery"


class IngestPayload(BaseModel):
    """A patient uploads a record of their own through their key agent (P3-14).

    The custodian does what ``demo/seed_data.py`` does for the synthetic
    dataset: mints and 2-of-3-splits the record's emergency key (share 3 to
    the audit service, share 1 to clinician custody here), obtains the
    authoring attribute keys the ``clinical_policy`` leaves reference plus the
    patient's own ``owner:<patient_id>`` key, and hands the bytes to the
    facility's ``/records/ingest``, which encrypts, compiles the policy with
    the owner leaf added (ADR-0016), wraps the DEK and indexes the terms. The
    portal never sees a key and never writes the store.
    """

    facility_id: str = Field(..., description="Facility that will hold the record")
    content_b64: str = Field(..., description="Base64 of the file's bytes")
    content_type: str = "application/octet-stream"
    clinical_policy: PolicyTree
    search_terms: list[str] = Field(default_factory=list)
    record_id: str | None = None


class IngestResult(BaseModel):
    record_id: str
    facility_id: str
    patient_id: str
    policy_id: str
    lifecycle_state: str
    search_terms_indexed: int
    audit_share_deposited: bool
    detail: str = "Record encrypted at the facility; owner leaf present"


class ErrorResponse(BaseModel):
    detail: str
    denied_by: str | None = None
    upstream: dict[str, Any] | None = None
