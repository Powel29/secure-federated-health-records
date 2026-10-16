"""Validate a person's certificate for a named subject (ADR-0064, ADR-0080).

Patients and clinicians are certified by their home facility CA. A verifier
-- a facility checking a consent request, an authority checking who asks for
an attribute key -- accepts a signature only under a key certified by a
facility CA it is configured to trust, never under a key the caller supplies.

The role is the certificate's OU: ``patient`` for a patient, none for a
clinician (``identity.certificates``), ``service:<kind>`` for a federation
service. A caller names the roles it accepts, so neither stands in for the
other.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping

from crypto_core import InvalidSignatureError, certificate_role
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from identity.certificates import PATIENT_ROLE
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError, SubjectCertificateError

# A clinician certificate carries no OU (``issue_clinician_certificate``).
CLINICIAN_ROLE: str | None = None
PERSON_ROLES: frozenset[str | None] = frozenset({PATIENT_ROLE, CLINICIAN_ROLE})


def validate_subject_certificate(
    certificate: Certificate,
    *,
    subject_id: str,
    roles: frozenset[str | None],
    facility_cas: Mapping[str, Certificate],
    trusted_root: Certificate,
    revoked_serials: frozenset[int] = frozenset(),
    at: datetime.datetime | None = None,
) -> str | None:
    """Fail closed unless ``certificate`` is ``subject_id``'s, from a trusted CA.

    Args:
        certificate: The presented certificate.
        subject_id: The subject it must belong to (its CN).
        roles: The roles (OUs) accepted; ``None`` stands for no OU.
        facility_cas: The configured facility CAs, one of which must have
            issued it.
        trusted_root: The federation root those CAs chain to.
        revoked_serials: Serial numbers of revoked certificates.
        at: The instant to check validity against; defaults to now.

    Returns:
        The certificate's role.

    Raises:
        ChainValidationError: No configured CA issued it, or its chain does
            not verify (a broken signature is reported as a broken chain).
        CertificateExpiredError: A certificate in the chain is out of date.
        SubjectCertificateError: Its role is not accepted, it names another
            subject, or it is revoked.
    """
    issuer = next(
        (ca for ca in facility_cas.values() if ca.subject == certificate.issuer),
        None,
    )
    if issuer is None:
        raise ChainValidationError(
            "certificate was not issued by a configured facility CA"
        )
    try:
        validate_chain(certificate, [issuer], trusted_root, at=at)
    except InvalidSignatureError as exc:
        raise ChainValidationError(f"certificate chain does not verify: {exc}") from exc
    role = certificate_role(certificate)
    if role not in roles:
        raise SubjectCertificateError(f"certificate role {role!r} is not accepted")
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or str(names[0].value) != subject_id:
        raise SubjectCertificateError(f"certificate does not belong to {subject_id!r}")
    if certificate.serial_number in revoked_serials:
        raise SubjectCertificateError(
            f"certificate serial {certificate.serial_number} is revoked"
        )
    return role
