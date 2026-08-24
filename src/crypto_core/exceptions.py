"""Exceptions raised by crypto_core operations (owner module: ``crypto_core``, C1)."""

from __future__ import annotations


class CryptoError(Exception):
    """Base exception for all cryptographic errors in crypto_core."""


class InvalidTagError(CryptoError):
    """Raised when symmetric ciphertext authentication fails (e.g. tag mismatch)."""


class InvalidSignatureError(CryptoError):
    """Raised when asymmetric signature verification fails."""


class KeyFormatError(CryptoError):
    """Raised when a key cannot be parsed or deserialized."""
