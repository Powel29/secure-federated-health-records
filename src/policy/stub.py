"""Access policy engine stub (owner module: ``policy``, C7).

Provides a deterministic fake stand-in for the access structure engine (P1-6)
that evaluates PolicyTree structures against presented attributes, unblocking
downstream development before the full Shamir compiler lands in Phase 2.
"""

from __future__ import annotations

from collections.abc import Iterable

from contracts.base import Attribute
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree

from policy.exceptions import PolicyDeniedError


def _normalize_attributes(
    attributes: Iterable[Attribute | tuple[str, str]],
) -> set[tuple[str, str]]:
    """Normalize attributes into a set of (name, value) string tuples."""
    normalized: set[tuple[str, str]] = set()
    for attr in attributes:
        if isinstance(attr, Attribute):
            normalized.add((attr.name, attr.value))
        elif isinstance(attr, tuple) and len(attr) == 2:
            normalized.add((str(attr[0]), str(attr[1])))
        else:
            raise TypeError(f"Invalid attribute format: {attr}")
    return normalized


def evaluate_policy(
    tree: PolicyTree,
    presented_attributes: Iterable[Attribute | tuple[str, str]],
) -> bool:
    """Evaluate whether presented attributes satisfy an access policy tree.

    Args:
        tree: The PolicyTree contract representing the access policy.
        presented_attributes: An iterable of Attribute objects or (name, value) tuples.

    Returns:
        True if the policy is satisfied, False otherwise.

    Security property:
        Fails closed on any unsatisfied leaf, uncertified attribute, or empty tree.
    """
    attr_set = _normalize_attributes(presented_attributes)

    if tree.node_type is PolicyNodeType.LEAF:
        if tree.attribute is None:
            return False
        return (tree.attribute.name, tree.attribute.value) in attr_set

    if tree.node_type is PolicyNodeType.AND:
        if not tree.children:
            return False
        return all(evaluate_policy(child, attr_set) for child in tree.children)

    if tree.node_type is PolicyNodeType.OR:
        if not tree.children:
            return False
        return any(evaluate_policy(child, attr_set) for child in tree.children)

    return False


def evaluate_and_unwrap_stub(
    tree: PolicyTree,
    presented_attributes: Iterable[Attribute | tuple[str, str]],
    root_key: bytes,
) -> bytes:
    """Simulate policy evaluation and DEK unwrapping.

    Args:
        tree: The PolicyTree governing the record.
        presented_attributes: Attributes held by the requester.
        root_key: The expected key to return on success.

    Returns:
        The root_key bytes if the policy is satisfied.

    Raises:
        PolicyDeniedError: If presented attributes do not satisfy the policy tree.

    Security property:
        Fails closed when attributes are insufficient (CONVENTIONS.md §2 rule 6).
    """
    if not evaluate_policy(tree, presented_attributes):
        raise PolicyDeniedError("Presented attributes do not satisfy the policy tree")
    return root_key
