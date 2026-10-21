"""Threshold secret sharing (owner module: ``shamir``, C2).

Provides (k, n) threshold secret sharing over a prime field GF(P).
Used by both the break-glass 3-of-4 threshold gate (ADR-0089) and the policy
engine.
"""

from __future__ import annotations

from shamir.exceptions import (
    DuplicateShareError,
    InsufficientSharesError,
    InvalidShareError,
    SecretSharingError,
)
from shamir.split import combine_shares, split_secret

__all__ = [
    "DuplicateShareError",
    "InsufficientSharesError",
    "InvalidShareError",
    "SecretSharingError",
    "combine_shares",
    "split_secret",
]
