"""Validate a federation service certificate (ADR-0066, review D5-a).

Every request one federation service sends another carries the caller's
service certificate and a signed ``RequestEnvelope``. The callee trusts the
caller's id and kind only once this check passes: the certificate chains
directly to the federation root and is marked as a service certificate.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from crypto_core import InvalidSignatureError, certificate_role, is_ca_certificate
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID

from identity.certificates import SERVICE_KINDS, SERVICE_ROLE_PREFIX
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError, ServiceCertificateError


@dataclass(frozen=True)
class ServiceName:
    """The identity a valid service certificate names."""

    service_id: str
    kind: str


def service_name(certificate: Certificate) -> ServiceName:
    """Read the service id (CN) and kind (OU) a certificate claims.

    Does not check the chain -- :func:`validate_service_certificate` does.

    Raises:
        ServiceCertificateError: It is a CA certificate, carries no CN, or its
            OU is not ``service:<known kind>``.
    """
    if is_ca_certificate(certificate):
        raise ServiceCertificateError("a CA certificate is not a service identity")
    role = certificate_role(certificate) or ""
    if not role.startswith(SERVICE_ROLE_PREFIX):
        raise ServiceCertificateError("certificate is not a service certificate")
    kind = role[len(SERVICE_ROLE_PREFIX) :]
    if kind not in SERVICE_KINDS:
        raise ServiceCertificateError(f"unknown service kind {kind!r}")
    names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not names or not str(names[0].value):
        raise ServiceCertificateError("service certificate has no common name")
    return ServiceName(service_id=str(names[0].value), kind=kind)


def validate_service_certificate(
    certificate: Certificate,
    *,
    trusted_root: Certificate,
    at: datetime.datetime | None = None,
) -> ServiceName:
    """Fail closed unless ``certificate`` is a root-issued service certificate.

    Args:
        certificate: The certificate a caller presented.
        trusted_root: The federation root from this service's configuration,
            never from the request.
        at: The instant to check validity against; defaults to now.

    Returns:
        The caller's service id and kind.

    Raises:
        ChainValidationError: It was not issued by ``trusted_root`` (a broken
            signature is reported as a broken chain).
        CertificateExpiredError: It is outside its validity window.
        ServiceCertificateError: It is not marked as a service certificate.
    """
    name = service_name(certificate)
    try:
        validate_chain(certificate, [], trusted_root, at=at)
    except InvalidSignatureError as exc:
        raise ChainValidationError(
            f"service certificate chain does not verify: {exc}"
        ) from exc
    return name
