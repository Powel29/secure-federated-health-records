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
    authority (P3-12). Raised when an unauthorized party (e.g. a clinician,
    foreign authority, or another patient) attempts to revoke a record."""
