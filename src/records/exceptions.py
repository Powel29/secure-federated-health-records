"""Exceptions for record encryption and DEK management (module: ``records``, C8)."""

from __future__ import annotations


class RecordError(Exception):
    """Base exception for all errors in the records module."""


class DecryptionError(RecordError):
    """Raised when record payload decryption or authentication fails."""


class UnwrappingError(RecordError):
    """Raised when DEK unwrapping fails (e.g. wrong key or tampered wrapping)."""
