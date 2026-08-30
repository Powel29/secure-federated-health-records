"""Access structure engine: AND/OR policy tree over Shamir (``policy``, C7).

This is the real CP-ABE substitute (ARCHITECTURE.md §3, ADR-0002), replacing the
P1-6 boolean stub. The construction is exactly the one §3 specifies and is not
improvised (see ADR-0026):

- The **root secret** is the wrapping key for a record's DEK (32 bytes).
- An **AND** node k-of-k Shamir-splits its parent's secret across its children;
  all children are needed to reconstruct.
- An **OR** node gives every child the *same* secret; any one child suffices.
- A **leaf**'s secret is AES-256-GCM-encrypted to the attribute key issued by
  the authority that owns that attribute; only a holder of that key recovers it.

A requester holding attribute keys that satisfy the tree decrypts the satisfying
leaves and reconstructs up to the root secret, which unwraps the DEK. Nobody is
pre-provisioned per record, and leaves may be owned by different federated
authorities -- the property the project needs for cross-institution access.

Two roles are kept distinct (ARCHITECTURE.md §8): :func:`evaluate_policy` is the
cheap boolean **Policy Decision Point**; :func:`reconstruct_root_secret` and
:func:`unwrap_dek_via_policy` are the enforcing **Policy Enforcement Point** --
they release nothing unless the held keys actually decrypt the tree.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from contracts.base import Attribute
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree
from contracts.records import DEKWrapping
from crypto_core import aes_gcm_decrypt, aes_gcm_encrypt
from crypto_core.exceptions import InvalidTagError
from records import unwrap_dek
from shamir import combine_shares, split_secret

from policy.exceptions import PolicyCompileError, PolicyDeniedError

# A keyring maps an owned attribute -- identified by (authority_id, name, value)
# -- to that authority's 32-byte attribute key. The compile-time keyring is the
# issuing authorities' keys; the reconstruct-time keyring is the subset a
# requester actually holds. Keying by authority_id as well as name/value binds a
# leaf to its owning authority: a key for the same name:value issued by a
# different authority does not appear under this leaf's entry and cannot open it.
AttributeKey = tuple[str, str, str]  # (authority_id, attribute.name, attribute.value)
AttributeKeyring = Mapping[AttributeKey, bytes]

OWNER_ATTRIBUTE_NAME = "owner"  # ADR-0016 patient self-access leaf


@dataclass(frozen=True)
class CompiledLeaf:
    """A compiled leaf: the leaf secret sealed under its authority's attribute key."""

    attribute: Attribute
    authority_id: str
    encrypted_share: bytes  # AES-256-GCM ciphertext of the leaf secret
    nonce: bytes  # GCM nonce for ``encrypted_share``


@dataclass(frozen=True)
class CompiledInternal:
    """A compiled AND/OR node and, for AND, the Shamir x-coordinate of each child."""

    node_type: PolicyNodeType  # AND or OR
    children: tuple["CompiledNode", ...]
    child_x: tuple[int, ...]  # AND: the (x) each child's share sits at; OR: unused


CompiledNode = CompiledLeaf | CompiledInternal


@dataclass(frozen=True)
class CompiledPolicy:
    """A policy tree compiled into an encrypted Shamir sharing layout.

    Held in memory by the engine; serializing it for storage (so a later reader
    reconstructs against stored shares) is P3-14 / storage wiring, not P2-3
    (ADR-0026).
    """

    root: CompiledNode


def _leaf_key(attribute: Attribute, authority_id: str) -> AttributeKey:
    """The keyring lookup key for a leaf: its owning authority plus its attribute."""
    return (authority_id, attribute.name, attribute.value)


def _normalize_attributes(
    attributes: Iterable[Attribute | tuple[str, str]],
) -> set[tuple[str, str]]:
    """Normalize attributes into a set of ``(name, value)`` string tuples."""
    normalized: set[tuple[str, str]] = set()
    for attr in attributes:
        if isinstance(attr, Attribute):
            normalized.add((attr.name, attr.value))
        elif isinstance(attr, tuple) and len(attr) == 2:
            normalized.add((str(attr[0]), str(attr[1])))
        else:
            raise TypeError(f"Invalid attribute format: {attr!r}")
    return normalized


def evaluate_policy(
    tree: PolicyTree,
    presented_attributes: Iterable[Attribute | tuple[str, str]],
) -> bool:
    """Boolean check (PDP): do the presented attributes satisfy the policy tree?

    Args:
        tree: The policy tree.
        presented_attributes: Attribute objects or ``(name, value)`` tuples.

    Returns:
        True if the attribute set satisfies the tree, False otherwise.

    Security property:
        This is a *decision*, not enforcement -- it is authority-agnostic and
        holds no keys. Access is only actually granted by
        :func:`reconstruct_root_secret`, which fails closed on key possession.
        Retained with the P1-6 stub's signature so existing callers are
        unchanged (P2-3 "drops in without changing callers").
    """
    attr_set = _normalize_attributes(presented_attributes)
    return _evaluate_node(tree, attr_set)


def _evaluate_node(node: PolicyTree, attr_set: set[tuple[str, str]]) -> bool:
    """Recursively evaluate a policy node against a normalized attribute set."""
    if node.node_type is PolicyNodeType.LEAF:
        # A well-formed leaf always carries an attribute (PolicyTree validator),
        # but fail closed rather than assume it.
        if node.attribute is None:
            return False
        return (node.attribute.name, node.attribute.value) in attr_set
    if node.node_type is PolicyNodeType.AND:
        return all(_evaluate_node(child, attr_set) for child in node.children)
    if node.node_type is PolicyNodeType.OR:
        return any(_evaluate_node(child, attr_set) for child in node.children)
    return False  # unknown node type: fail closed


def compile_policy(
    tree: PolicyTree,
    root_secret: bytes,
    attribute_keyring: AttributeKeyring,
) -> CompiledPolicy:
    """Compile a policy tree into an encrypted Shamir layout under ``root_secret``.

    Args:
        tree: The access-policy tree (ARCHITECTURE.md §3).
        root_secret: The 32-byte secret that wraps the record's DEK; it becomes
            the secret held at the root of the tree.
        attribute_keyring: The issuing authorities' attribute keys, keyed
            ``(authority_id, name, value)``. Every leaf the tree references must
            have an entry.

    Returns:
        The compiled policy: each leaf secret sealed under its authority's key.

    Raises:
        PolicyCompileError: A leaf references an attribute with no key in the
            keyring.

    Security property:
        Each leaf secret is AES-256-GCM-encrypted under the owning authority's
        key with a fresh nonce (CONVENTIONS.md §2 rule 5). AND nodes split
        k-of-k so no proper subset of an AND's children can reconstruct it.
    """
    return CompiledPolicy(root=_compile_node(tree, root_secret, attribute_keyring))


def _compile_node(
    node: PolicyTree, secret: bytes, keyring: AttributeKeyring
) -> CompiledNode:
    """Recursively seal a policy node given the secret flowing into it."""
    if node.node_type is PolicyNodeType.LEAF:
        # PolicyTree's validator guarantees these on a leaf, but fail closed
        # rather than assume (an assert would be stripped under -O).
        if node.attribute is None or node.authority_id is None:
            raise PolicyCompileError("leaf node missing attribute or authority_id")
        key = keyring.get(_leaf_key(node.attribute, node.authority_id))
        if key is None:
            raise PolicyCompileError(
                f"no attribute key for {node.attribute.name}:{node.attribute.value} "
                f"owned by {node.authority_id!r}"
            )
        ciphertext, nonce = aes_gcm_encrypt(key=key, plaintext=secret)
        return CompiledLeaf(
            attribute=node.attribute,
            authority_id=node.authority_id,
            encrypted_share=ciphertext,
            nonce=nonce,
        )

    if node.node_type is PolicyNodeType.AND:
        # k-of-k: every child is required. split_secret returns shares at x=1..m
        # in child order; each child subtree receives its share as its secret.
        m = len(node.children)
        shares = split_secret(secret, k=m, n=m)
        children = tuple(
            _compile_node(child, share_bytes, keyring)
            for child, (_x, share_bytes) in zip(node.children, shares, strict=True)
        )
        return CompiledInternal(
            node_type=PolicyNodeType.AND,
            children=children,
            child_x=tuple(x for x, _share in shares),
        )

    if node.node_type is PolicyNodeType.OR:
        # Every child receives the same secret; any one suffices to recover it.
        children = tuple(
            _compile_node(child, secret, keyring) for child in node.children
        )
        return CompiledInternal(
            node_type=PolicyNodeType.OR,
            children=children,
            child_x=tuple(1 for _ in node.children),  # unused for OR
        )

    raise PolicyCompileError(f"unknown policy node type {node.node_type!r}")


def reconstruct_root_secret(
    compiled: CompiledPolicy,
    holder_keyring: AttributeKeyring,
) -> bytes:
    """Reconstruct the root secret using the attribute keys the holder possesses.

    Args:
        compiled: A policy compiled by :func:`compile_policy`.
        holder_keyring: The attribute keys this requester holds, keyed
            ``(authority_id, name, value)``.

    Returns:
        The reconstructed root secret (the DEK wrapping key).

    Raises:
        PolicyDeniedError: The held keys do not satisfy the tree -- a required
            leaf could not be decrypted, so the root cannot be rebuilt.

    Security property:
        Enforcement (PEP). Fails closed: reconstruction returns ``None``
        internally at any unsatisfiable node and is surfaced here as a denial,
        never a partial or default secret (CONVENTIONS.md §2 rule 6).
    """
    secret = _reconstruct_node(compiled.root, holder_keyring)
    if secret is None:
        raise PolicyDeniedError("held attribute keys do not satisfy the policy tree")
    return secret


def _reconstruct_node(node: CompiledNode, holder: AttributeKeyring) -> bytes | None:
    """Recover a node's secret, or ``None`` if the holder cannot satisfy it."""
    if isinstance(node, CompiledLeaf):
        key = holder.get(_leaf_key(node.attribute, node.authority_id))
        if key is None:
            return None  # holder lacks this attribute key -> leaf unsatisfied
        try:
            return aes_gcm_decrypt(
                key=key, nonce=node.nonce, ciphertext=node.encrypted_share
            )
        except InvalidTagError:
            # A present-but-wrong key (or corrupted share) means this holder does
            # not satisfy the leaf. Swallowing is correct here: it propagates to a
            # top-level PolicyDeniedError (fail closed), never to access granted.
            return None

    if node.node_type is PolicyNodeType.AND:
        # k-of-k: every child's secret is required to combine.
        recovered: list[tuple[int, bytes]] = []
        for child, x in zip(node.children, node.child_x, strict=True):
            child_secret = _reconstruct_node(child, holder)
            if child_secret is None:
                return None  # any missing child -> AND cannot be reconstructed
            recovered.append((x, child_secret))
        return combine_shares(recovered, k=len(node.children))

    # OR: the first child that yields a secret suffices (all are identical).
    for child in node.children:
        child_secret = _reconstruct_node(child, holder)
        if child_secret is not None:
            return child_secret
    return None


def unwrap_dek_via_policy(
    compiled: CompiledPolicy,
    holder_keyring: AttributeKeyring,
    wrapping: DEKWrapping,
) -> bytes:
    """Reconstruct the root secret and use it to unwrap a record's DEK (PEP).

    Args:
        compiled: The record's compiled policy.
        holder_keyring: The requester's held attribute keys.
        wrapping: The record's DEK wrapping, sealed under the root secret.

    Returns:
        The recovered 32-byte DEK.

    Raises:
        PolicyDeniedError: The held keys do not satisfy the policy tree.
        UnwrappingError: The reconstructed secret did not unwrap the DEK (e.g.
            the wrapping belongs to a different policy).

    Security property:
        The single decryption path (ADR-0016): patient and clinician reads both
        go through policy reconstruction, then DEK unwrap. No side channel to a
        DEK exists.
    """
    root_secret = reconstruct_root_secret(compiled, holder_keyring)
    return unwrap_dek(wrapping, root_secret)


def author_policy_with_owner(
    clinical_policy: PolicyTree,
    patient_id: str,
    owner_authority_id: str,
) -> PolicyTree:
    """Wrap a clinical policy in the ADR-0016 root ``OR`` with an owner leaf.

    Every record's tree is authored as ``OR(clinical_policy, owner:<patient_id>)``
    so the patient can always reconstruct their own record via the same path a
    clinician uses. This is a construction convention, not a schema change --
    the returned value is an ordinary :class:`PolicyTree`.

    Args:
        clinical_policy: The clinical access branch (any policy subtree).
        patient_id: The record's patient; becomes the ``owner`` leaf's value.
        owner_authority_id: The patient's home authority that owns the ``owner``
            namespace (ADR-0019) and issues the ``owner:<patient_id>`` key.

    Returns:
        A root ``OR`` policy tree with the clinical policy and the owner leaf.
    """
    owner_leaf = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=OWNER_ATTRIBUTE_NAME, value=patient_id),
        authority_id=owner_authority_id,
    )
    return PolicyTree(
        node_type=PolicyNodeType.OR,
        children=(clinical_policy, owner_leaf),
    )
