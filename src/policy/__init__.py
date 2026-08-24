"""Access policy engine (owner module: ``policy``, C7).

Provides policy evaluation over AND/OR attribute trees (ARCHITECTURE.md §3, ADR-0002).
"""

from __future__ import annotations

from policy.exceptions import PolicyDeniedError, PolicyError
from policy.stub import evaluate_and_unwrap_stub, evaluate_policy

__all__ = [
    "PolicyDeniedError",
    "PolicyError",
    "evaluate_and_unwrap_stub",
    "evaluate_policy",
]
