"""Access-policy tree contract (owner module: ``policy``, C7).

Models the AND/OR attribute tree of ARCHITECTURE.md §3. The tree is data only;
compiling it into a Shamir sharing layout and reconstructing the DEK is the
policy engine's job, not the contract's.
"""

from __future__ import annotations

from pydantic import model_validator

from contracts.base import Attribute, ContractModel, Identifier
from contracts.enums import PolicyNodeType


class PolicyTree(ContractModel):
    """A node in a record's access-policy tree (ARCHITECTURE.md §3).

    A node is exactly one of:

    - a **leaf** -- carries an :class:`Attribute` and the id of the authority
      that owns that attribute; no children.
    - an **AND** / **OR** node -- carries two or more children and no attribute.
      AND splits its secret k-of-k across children; OR gives each child the same
      secret.
    """

    node_type: PolicyNodeType
    # Leaf-only fields:
    attribute: Attribute | None = None
    authority_id: Identifier | None = None  # authority that owns the attribute
    # Internal-node-only field:
    children: tuple["PolicyTree", ...] = ()

    @model_validator(mode="after")
    def _well_formed(self) -> "PolicyTree":
        """Enforce the leaf/internal shape invariant, fail closed on a mix.

        Security property: a malformed tree (a leaf with children, or an AND with
        an attribute) is ambiguous to the sharing compiler and could collapse a
        multi-attribute policy into a weaker one. The contract rejects it here.
        """
        if self.node_type is PolicyNodeType.LEAF:
            if self.attribute is None or self.authority_id is None:
                raise ValueError("leaf node requires attribute and authority_id")
            if self.children:
                raise ValueError("leaf node must not have children")
        else:  # AND / OR
            if self.attribute is not None or self.authority_id is not None:
                raise ValueError("internal node must not carry an attribute")
            if len(self.children) < 2:
                raise ValueError(
                    f"{self.node_type.value} node requires at least 2 children"
                )
        return self


# Self-referential model: resolve the forward reference in ``children``.
PolicyTree.model_rebuild()
