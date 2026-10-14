"""Exceptions raised by the identity module (owner module: ``identity``, C5)."""

from __future__ import annotations

from crypto_core import CryptoError


class ChainValidationError(CryptoError):
    """Raised when a certificate chain does not validate back to a trusted root.

    Covers every failure mode of chain walking that is not already a more
    specific ``crypto_core`` exception: a broken issuer/subject link, an
    intermediate missing the CA basic constraint, or a chain that terminates
    at a root the caller does not trust.
    """


class UnknownFacilityError(CryptoError):
    """Raised when a facility id has no registered certificate to validate against."""


class PatientCertificateError(CryptoError):
    """Raised when a certificate is not a valid certificate for the named patient.

    Covers a certificate that is not marked as a patient's, names another
    patient, or is revoked (ADR-0064). Chain failures raise
    :class:`ChainValidationError`.
    """
