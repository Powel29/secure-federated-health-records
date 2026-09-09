"""Pydantic schemas for the standalone Attribute Authority Service (P4-2, C14/C6).

Wire-format request and response bodies only. No cryptographic computation
happens here (CONVENTIONS.md §2 rule 10) -- ``authority_service.py``
orchestrates calls into ``authority.issuance``, which is where every
signature and key release actually happens.
"""

from __future__ import annotations

import datetime

from contracts import Attribute, AttributeCredential
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str = "ok"
    authority_id: str


class PublicKeyResponse(BaseModel):
    """This authority's ECDSA-P256 public key, for credential verification."""

    public_key_pem: str


class CertificateResponse(BaseModel):
    """This authority's identity certificate, once the root has issued one.

    ``None`` before bootstrap has called ``PUT /certificate`` -- that call is
    ARCHITECTURE.md §7 step 3's "registers its public parameters with the
    anchor," performed by the deployment bootstrap script (P4-3), not by
    this service itself (it has no access to the root's private key).
    """

    certificate_pem: str | None


class SetCertificateRequest(BaseModel):
    certificate_pem: str


class IssueCredentialRequest(BaseModel):
    """Issue a signed attribute credential to ``subject_id``.

    Set ``owner=True`` for the ADR-0016 ``owner:<patient_id>`` case: the
    authority then issues ``attribute.name="owner"``,
    ``attribute.value=subject_id`` regardless of what ``attribute`` names,
    matching ``authority.issuance.issue_owner_credential``.
    """

    subject_id: str
    attribute: Attribute
    valid_from: datetime.datetime | None = None
    valid_until: datetime.datetime | None = None
    owner: bool = False


class IssueCredentialResponse(BaseModel):
    credential: AttributeCredential


class VerifyCredentialRequest(BaseModel):
    credential: AttributeCredential


class VerifyCredentialResponse(BaseModel):
    valid: bool = True


class CredentialStatusRequest(BaseModel):
    credential: AttributeCredential


class CredentialStatusResponse(BaseModel):
    status: str


class RevokeCredentialResponse(BaseModel):
    serial: str
    revoked_at: datetime.datetime
    reason: str


class AttributeKeyReleaseRequest(BaseModel):
    """Exchange a valid credential for the attribute key it certifies (§8 C6)."""

    credential: AttributeCredential


class AttributeKeyResponse(BaseModel):
    name: str
    value: str
    key_b64: str


class AuthorAttributeKeyRequest(BaseModel):
    """Authoring-side key mint/lookup, used to seal a policy leaf at ingest.

    Unlike ``AttributeKeyReleaseRequest``, this is not credential-gated --
    it is how a policy author (record ingest, P3-14) obtains the key to seal
    a leaf in the first place, before any holder presents a credential for
    it. ARCHITECTURE.md §8 deliberately excludes session/auth infrastructure
    from this project's scope; a production deployment would restrict this
    endpoint to trusted policy-authoring callers only -- documented
    limitation, not a claimed control.
    """

    name: str
    value: str


class ErrorResponse(BaseModel):
    detail: str
