"""Patient-signed clinical labels and the disclosure rules they set (ADR-0064).

PR #40 put each record's clinical labels (source, sensitivity, care-team
consent) in a plain column of the shared store, and the facility decides from
them whether break-glass needs a written justification and whether a clinician
read needs the patient's consent. A store write could therefore loosen the
rules. Here the labels carry the patient's signature, bound to the record and
patient ids, verified against a patient certificate from a configured facility
CA. Labels that are unsigned or do not verify get the strictest rules, so
removing or editing them can only make access harder, never easier.

The labels stay readable in the store; this protects their integrity, not
their confidentiality.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace

from contracts.clinical import ClinicalMetadata
from contracts.records import Record
from crypto_core import (
    CryptoError,
    certificate_from_pem,
    certificate_public_key,
    sign,
    verify,
)
from crypto_core.types import ECPrivateKey
from cryptography.x509 import Certificate
from identity import validate_patient_certificate

from records.exceptions import RecordError

# Domain-separates this signature from every other one a patient key makes.
_LABELS_DOMAIN = "clinical-labels-v1"


class LabelVerificationError(RecordError):
    """The record's labels are unsigned, or their signature does not verify."""


@dataclass(frozen=True)
class LabelTrust:
    """What a verifier trusts: the federation root and configured facility CAs."""

    facility_cas: Mapping[str, Certificate]
    trusted_root: Certificate
    revoked_serials: frozenset[int] = frozenset()


@dataclass(frozen=True)
class DisclosureRules:
    """What a record's labels require before its contents are released."""

    labels_verified: bool
    clinical_justification: bool  # break-glass must state the clinical need
    sensitive_justification: bool  # break-glass must justify a restricted record
    consent_for_read: bool  # a clinician read needs a patient-signed grant
    reason: str = ""


# Unsigned or unverifiable labels: every requirement applies.
STRICTEST_RULES = DisclosureRules(
    labels_verified=False,
    clinical_justification=True,
    sensitive_justification=True,
    consent_for_read=True,
)


def labels_payload(
    clinical: ClinicalMetadata, *, record_id: str, patient_id: str
) -> bytes:
    """The canonical bytes the patient signs: every label plus both ids.

    A JSON array of strings, so free-text fields such as the title cannot be
    crafted to shift one field into another.
    """
    fields = [
        _LABELS_DOMAIN,
        record_id,
        patient_id,
        clinical.title,
        clinical.author_id,
        clinical.clinical_date.isoformat() if clinical.clinical_date else "",
        clinical.record_type,
        clinical.episode_id,
        clinical.source,
        clinical.sensitivity,
        "true" if clinical.care_team_consent else "false",
    ]
    return json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sign_clinical_labels(
    clinical: ClinicalMetadata,
    *,
    record_id: str,
    patient_id: str,
    signing_key: ECPrivateKey,
    certificate_pem: str,
) -> ClinicalMetadata:
    """Return ``clinical`` signed by the patient's key, with their certificate."""
    unsigned = clinical.model_copy(
        update={"signature": None, "signer_certificate_pem": None}
    )
    signature = sign(
        signing_key,
        labels_payload(unsigned, record_id=record_id, patient_id=patient_id),
    )
    return unsigned.model_copy(
        update={"signature": signature, "signer_certificate_pem": certificate_pem}
    )


def verify_clinical_labels(record: Record, trust: LabelTrust) -> None:
    """Fail closed unless the record's labels carry its patient's valid signature.

    Raises:
        LabelVerificationError: Unsigned, the certificate is not this
            patient's from a configured facility CA, or the signature does
            not cover exactly these labels for this record.
    """
    clinical = record.clinical
    if clinical.signature is None or not clinical.signer_certificate_pem:
        raise LabelVerificationError("clinical labels are not signed")
    try:
        certificate = certificate_from_pem(clinical.signer_certificate_pem.encode())
        validate_patient_certificate(
            certificate,
            patient_id=record.patient_id,
            facility_cas=trust.facility_cas,
            trusted_root=trust.trusted_root,
            revoked_serials=trust.revoked_serials,
        )
        verify(
            certificate_public_key(certificate),
            labels_payload(
                clinical, record_id=record.record_id, patient_id=record.patient_id
            ),
            clinical.signature,
        )
    except CryptoError as exc:
        raise LabelVerificationError(f"clinical labels do not verify: {exc}") from exc


def disclosure_rules(record: Record, trust: LabelTrust | None) -> DisclosureRules:
    """The rules a record's labels set -- the strictest unless they verify."""
    if trust is None:
        return replace(STRICTEST_RULES, reason="no trust anchors configured")
    try:
        verify_clinical_labels(record, trust)
    except LabelVerificationError as exc:
        return replace(STRICTEST_RULES, reason=str(exc))
    clinical = record.clinical
    return DisclosureRules(
        labels_verified=True,
        clinical_justification=clinical.source != "unknown",
        sensitive_justification=clinical.sensitivity != "general",
        consent_for_read=clinical.care_team_consent or clinical.source != "unknown",
    )
