"""Exceptions for Proxy Re-Encryption operations (owner module: ``pre``, C3)."""

from __future__ import annotations


class PREError(Exception):
    """Base exception for all Proxy Re-Encryption errors."""


class PREKeyError(PREError):
    """Raised when keys or parameters are malformed or outside valid bounds."""


class PREDecryptionError(PREError):
    """Raised when decapsulation or PRE transformation fails."""
