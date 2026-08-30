"""Exceptions for policy evaluation (owner module: ``policy``, C7)."""

from __future__ import annotations


class PolicyError(Exception):
    """Base exception for all policy engine errors."""


class PolicyDeniedError(PolicyError):
    """Raised when presented credentials do not satisfy the policy tree.

    This is the fail-closed outcome of reconstruction: a requester who cannot
    decrypt enough leaf shares to rebuild the root secret is denied, never
    handed a partial or default result (CONVENTIONS.md §2 rule 6).
    """


class PolicyCompileError(PolicyError):
    """Raised when a policy tree cannot be compiled into a Shamir sharing layout.

    The usual cause is an attribute keyring missing the key for a leaf the tree
    references -- a policy cannot be authored against an attribute whose owning
    authority has issued no key material for it.
    """
