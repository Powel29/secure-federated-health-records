"""The checks every break-glass share holder runs before releasing (ADR-0067, ADR-0089).

A share holder that releases without checking anything is a party that could
help open a record on a caller's say-so. So the audit service (shares 3 and 4)
and the patient's home authority (share 2) both run the identical check here
before any share moves:

1. the clinician's certificate parses and was issued by a federation facility
   CA from the holder's own configuration;
2. the assertion names a federation facility and is bound to a record: its
   signed clinical-context digest must name this ``share_key`` and match the
   justification texts (``breakglass.assertion.validate_clinical_context``);
3. the five-point check (ARCHITECTURE.md §8) passes against the holder's own
   trust anchors and its own consumed-assertion store
   (``breakglass.validate_emergency_assertion``);

and only then is the recipient verified as a root-certified facility gate
(:func:`verify_gate_recipient`), so shares are sealed to the facility that
will combine them, never to the caller forwarding them (ADR-0079).

No cryptography here (CONVENTIONS.md §2 rule 10): every signature and chain
check is in ``breakglass`` / ``identity``; this module maps their failures to
HTTP refusals, all fail-closed.
"""

from __future__ import annotations

from breakglass import ConsumedAssertionIds, validate_emergency_assertion
from breakglass.assertion import validate_clinical_context
from breakglass.exceptions import (
    AssertionExpiredError,
    AssertionLifetimeError,
    CertificateRevokedError,
    ClinicianMismatchError,
    FacilityMismatchError,
    ReplayedAssertionError,
    SealedShareError,
)
from breakglass.share_sealing import (
    ShareKeyStatement,
    ShareRecipient,
    verify_key_statement,
)
from contracts import EmergencyAssertion
from crypto_core import certificate_from_pem
from crypto_core.exceptions import (
    CertificateExpiredError,
    InvalidSignatureError,
    KeyFormatError,
)
from cryptography.x509 import Certificate
from fastapi import HTTPException, status
from identity.exceptions import ChainValidationError

from api.hospital import FacilityTrust


def check_release_assertion(
    *,
    trust: FacilityTrust | None,
    consumed_store: ConsumedAssertionIds,
    share_key: str,
    assertion: EmergencyAssertion,
    clinician_certificate_pem: str,
    justification: str,
    sensitive_justification: str,
    what: str,
) -> None:
    """Validate the emergency assertion before any share moves.

    Args:
        trust: The holder's own root, facility CAs and revoked serials.
            ``None`` refuses every release (503).
        consumed_store: The holder's own consumed-assertion set, kept apart
            from every other holder's (ADR-0067).
        share_key: The record the shares protect; the assertion's signed
            context digest must name it.
        assertion / clinician_certificate_pem: What the clinician signed,
            and the certificate that signs it.
        justification / sensitive_justification: Checked against the
            assertion's signed digest only; never logged.
        what: The shares refused, for the 503 message (e.g. ``"share 2"``).

    Raises:
        HTTPException: 503 without trust anchors; 400 for an unparsable
            certificate or an invalid assertion; 403 for a certificate, a
            facility or a record binding that is refused.
    """
    if trust is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"no trust anchors configured; {what} is not released",
        )
    try:
        certificate = certificate_from_pem(clinician_certificate_pem.encode("utf-8"))
    except KeyFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"clinician certificate does not parse: {exc}",
        ) from exc
    issuer = trust.issuing_ca(certificate)
    if issuer is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="clinician certificate was not issued by a federation CA",
        )
    if assertion.facility_id not in trust.facility_cas:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="assertion names a facility outside the federation",
        )
    if not assertion.clinical_context_digest:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="assertion is not bound to a record",
        )
    try:
        validate_clinical_context(
            assertion, share_key, justification, sensitive_justification
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"assertion is not for this record: {exc}",
        ) from exc
    try:
        validate_emergency_assertion(
            assertion=assertion,
            clinician_certificate=certificate,
            facility_ca_certificate=issuer[1],
            trusted_root=trust.root,
            expected_facility_id=assertion.facility_id,
            consumed_store=consumed_store,
            revoked_serials=trust.revoked_serials,
        )
    except (
        ChainValidationError,
        CertificateExpiredError,
        CertificateRevokedError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"clinician certificate refused: {exc}",
        ) from exc
    except (
        AssertionExpiredError,
        AssertionLifetimeError,
        ClinicianMismatchError,
        FacilityMismatchError,
        InvalidSignatureError,
        ReplayedAssertionError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"emergency assertion invalid ({exc.__class__.__name__}): {exc}",
        ) from exc


def verify_gate_recipient(
    statement: ShareKeyStatement, *, service_root: Certificate
) -> ShareRecipient:
    """The facility gate shares are sealed to, verified (ADR-0079).

    Raises:
        HTTPException: 403 if the statement is not a root-certified
            facility's.
    """
    try:
        return verify_key_statement(
            statement, trusted_root=service_root, kind="facility"
        )
    except SealedShareError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"share recipient refused: {exc}",
        ) from exc
