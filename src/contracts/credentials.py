"""Credential and facility contracts (owner modules: ``authority`` C6, ``identity`` C5).

``AttributeCredential`` is what an authority issues (C6); ``Facility`` describes a
federation node in the PKI/topology (C5, §7). Both are grouped here because both
are signed identity artifacts with a validity window and a status.
"""

from __future__ import annotations

from pydantic import AwareDatetime, field_validator, model_validator

from contracts.base import Attribute, B64Bytes, ContractModel, Identifier
from contracts.enums import CredentialStatus, FacilityStatus


class AttributeCredential(ContractModel):
    """A signed credential asserting that a subject holds an attribute (§2 C6).

    Carries the credential-lifecycle fields required by ARCHITECTURE.md §8:
    issuer, subject, serial, ``valid_from``, ``valid_until``, status. Only an
    ``ACTIVE`` credential inside its validity window passes verification; the
    ``policy`` engine trusts a satisfied leaf only for a valid credential.
    """

    serial: Identifier  # unique per issuer
    issuer_id: Identifier  # the authority (medical council, hospital network)
    subject_id: Identifier  # the clinician the attribute is bound to
    attribute: Attribute  # what is certified, e.g. role:physician
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    status: CredentialStatus
    signature: B64Bytes  # ECDSA by the issuing authority key

    @model_validator(mode="after")
    def _validity_window_ordered(self) -> "AttributeCredential":
        """A credential that expires no later than it starts is malformed."""
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        return self

    @field_validator("signature")
    @classmethod
    def _signature_present(cls, v: bytes) -> bytes:
        """An unsigned attribute credential grants nothing."""
        if len(v) == 0:
            raise ValueError("signature must not be empty")
        return v


class Facility(ContractModel):
    """A facility node in the federation (ARCHITECTURE.md §5 C5, §7).

    ``endpoint`` is configuration-sourced. Per CONVENTIONS.md §2 rule 8, a
    facility's address comes from the config allowlist, never from a value
    supplied in a request; this contract is how a config-loaded facility is
    represented, not a channel for a request to introduce one.
    """

    facility_id: Identifier
    display_name: str
    endpoint: str  # base URL, from the config allowlist
    public_key: B64Bytes  # facility CA / service public key (SPKI DER)
    status: FacilityStatus

    @field_validator("public_key")
    @classmethod
    def _public_key_present(cls, v: bytes) -> bytes:
        """A facility with no key cannot be authenticated."""
        if len(v) == 0:
            raise ValueError("public_key must not be empty")
        return v
