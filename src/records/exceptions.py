"""Exceptions for record encryption and DEK management (module: ``records``, C8)."""

from __future__ import annotations


class RecordError(Exception):
    """Base exception for all errors in the records module."""


class DecryptionError(RecordError):
    """Raised when record payload decryption or authentication fails."""


class UnwrappingError(RecordError):
    """Raised when DEK unwrapping fails (e.g. wrong key or tampered wrapping)."""


class RevocationError(RecordError):
    """Base exception for the revocation-by-key-rotation pipeline (P3-7)."""


class UnauthorizedRevocationError(RevocationError):
    """The actor attempting revocation is not the record's owner or its home
    authority. Reserved for the P3-12 authorization check — the P3-7 rotation
    pipeline does not itself enforce this, since who-can-revoke is a policy
    concern layered above the crypto rotation."""
