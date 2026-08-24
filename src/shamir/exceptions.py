"""Exceptions for Shamir secret sharing operations (owner: ``shamir``, C2)."""

from __future__ import annotations


class SecretSharingError(Exception):
    """Base exception for all errors in secret sharing."""


class InsufficientSharesError(SecretSharingError):
    """Raised when fewer than the threshold k shares are provided."""


class DuplicateShareError(SecretSharingError):
    """Raised when duplicate x-coordinates are detected among shares."""


class InvalidShareError(SecretSharingError):
    """Raised when a share payload is malformed or corrupted."""
