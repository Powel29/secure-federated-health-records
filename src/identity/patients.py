"""Validate a patient certificate for a named patient (ADR-0064).

A facility verifies a patient's signature -- on a record's clinical labels or
on a consent decision -- only against a key certified by a facility CA it is
configured to trust, never against a key the caller supplies.
"""

from __future__ import annotations

import datetime
from collections.abc import Mapping

from crypto_core import InvalidSignatureError, certificate_role
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from identity.certificates import PATIENT_ROLE
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError, PatientCertificateError


def validate_patient_certificate(
    certificate: Certificate,
    *,
    patient_id: str,
    facility_cas: Mapping[str, Certificate],
    trusted_root: Certificate,
    revoked_serials: frozenset[int] = frozenset(),
    at: datetime.datetime | None = None,
) -> None:
    """Fail closed unless ``certificate`` is ``patient_id``'s, from a trusted CA.

    Args:
        certificate: The presented patient certificate.
        patient_id: The patient it must belong to.
        facility_cas: The configured facility CAs, one of which must have
            issued it.
        trusted_root: The federation root those CAs chain to.
        revoked_serials: Serial numbers of revoked certificates.
        at: The instant to check validity against; defaults to now.

    Raises:
        ChainValidationError: No configured CA issued it, or its chain does
            not verify (a broken signature is reported as a broken chain).
        CertificateExpiredError: A certificate in the chain is out of date.
        PatientCertificateError: It is not a patient certificate, names
            another subject, or is revoked.
    """
    issuer = next(
        (ca for ca in facility_cas.values() if ca.subject == certificate.issuer),
        None,
    )
    if issuer is None:
        raise ChainValidationError(
            "patient certificate was not issued by a configured facility CA"
        )
    try:
        validate_chain(certificate, [issuer], trusted_root, at=at)
    except InvalidSignatureError as exc:
        raise ChainValidationError(
            f"patient certificate chain does not verify: {exc}"
        ) from exc
    if certificate_role(certificate) != PATIENT_ROLE:
        raise PatientCertificateError("certificate is not a patient certificate")
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or str(names[0].value) != patient_id:
        raise PatientCertificateError(
            f"certificate does not belong to patient {patient_id!r}"
        )
    if certificate.serial_number in revoked_serials:
        raise PatientCertificateError(
            f"patient certificate serial {certificate.serial_number} is revoked"
        )
