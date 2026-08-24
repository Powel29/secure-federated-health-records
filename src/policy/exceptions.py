"""Exceptions for policy evaluation (owner module: ``policy``, C7)."""

from __future__ import annotations


class PolicyError(Exception):
    """Base exception for all policy engine errors."""


class PolicyDeniedError(PolicyError):
    """Raised when presented credentials do not satisfy the policy tree."""
