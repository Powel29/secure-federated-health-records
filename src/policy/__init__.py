"""Access policy engine (owner module: ``policy``, C7).

The real access structure engine (ARCHITECTURE.md §3, ADR-0002, ADR-0026): an
AND/OR attribute tree over Shamir secret sharing, standing in for CP-ABE. A
requester holding attribute keys that satisfy the tree reconstructs the root
secret and unwraps the record's DEK; one who does not is refused, fail closed.
"""

from __future__ import annotations

from policy.engine import (
    AttributeKeyring,
    CompiledInternal,
    CompiledLeaf,
    CompiledPolicy,
    author_policy_with_owner,
    compile_policy,
    evaluate_policy,
    reconstruct_root_secret,
    unwrap_dek_via_policy,
)
from policy.exceptions import PolicyCompileError, PolicyDeniedError, PolicyError

__all__ = [
    "AttributeKeyring",
    "CompiledInternal",
    "CompiledLeaf",
    "CompiledPolicy",
    "PolicyCompileError",
    "PolicyDeniedError",
    "PolicyError",
    "author_policy_with_owner",
    "compile_policy",
    "evaluate_policy",
    "reconstruct_root_secret",
    "unwrap_dek_via_policy",
]
