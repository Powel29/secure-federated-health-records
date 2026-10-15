"""Exceptions raised by the authority module (owner module: ``authority``, C6)."""

from __future__ import annotations

from crypto_core import CryptoError


class UnauthorizedAttributeError(CryptoError):
    """Raised when an authority is asked to issue an attribute it does not own.

    Attribute-namespace ownership is fixed by ADR-0019 (e.g. ``authority-med``
    owns ``role:*``); an authority issuing outside its namespace would let any
    one authority mint any attribute, collapsing the multi-authority model.
    """


class CredentialStatusError(CryptoError):
    """Raised when a credential's ``status`` is not ``ACTIVE``."""


class CredentialRevokedError(CredentialStatusError):
    """Raised when a credential has been revoked post-issuance."""


class CredentialNotYetValidError(CryptoError):
    """Raised when a credential is checked before its ``valid_from``."""


class CredentialExpiredError(CryptoError):
    """Raised when a credential is checked after its ``valid_until``."""


class PossessionError(CryptoError):
    """Raised when a key-release request does not prove the subject is asking.

    The possession envelope is from someone other than the credential's
    subject, or covers another credential (ADR-0075, review F15).
    """
