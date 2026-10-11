"""JSON storage for compiled policies; only encrypted shares leave the engine."""

from __future__ import annotations

from typing import Any

from contracts.base import Attribute
from contracts.enums import PolicyNodeType
from policy.engine import CompiledInternal, CompiledLeaf, CompiledNode, CompiledPolicy


def encode_policy(policy: CompiledPolicy) -> dict[str, Any]:
    """Serialize the existing encrypted layout without storing attribute keys."""
    return {"version": 1, "root": _encode_node(policy.root)}


def _encode_node(node: CompiledNode) -> dict[str, Any]:
    if isinstance(node, CompiledLeaf):
        return {
            "node_type": "leaf",
            "attribute": node.attribute.model_dump(mode="json"),
            "authority_id": node.authority_id,
            "encrypted_share": node.encrypted_share.hex(),
            "nonce": node.nonce.hex(),
        }
    return {
        "node_type": node.node_type.value,
        "children": [_encode_node(child) for child in node.children],
        "child_x": list(node.child_x),
    }


def decode_policy(data: dict[str, Any]) -> CompiledPolicy:
    """Restore a compiled layout, rejecting unknown versions or malformed nodes."""
    # A bool is an int in Python: ``True == 1`` would otherwise pass (N15).
    version = data.get("version")
    if (
        set(data) != {"version", "root"}
        or isinstance(version, bool)
        or not isinstance(version, int)
    ):
        raise ValueError("unsupported compiled policy format")
    if data["version"] != 1:
        raise ValueError("unsupported compiled policy format")
    return CompiledPolicy(root=_decode_node(data["root"]))


def _decode_node(data: dict[str, Any]) -> CompiledNode:
    kind = PolicyNodeType(data["node_type"])
    if kind is PolicyNodeType.LEAF:
        if set(data) != {
            "node_type",
            "attribute",
            "authority_id",
            "encrypted_share",
            "nonce",
        }:
            raise ValueError("invalid compiled leaf fields")
        if not isinstance(data["authority_id"], str) or not data["authority_id"]:
            raise ValueError("invalid compiled leaf authority")
        nonce = bytes.fromhex(data["nonce"])
        share = bytes.fromhex(data["encrypted_share"])
        if len(nonce) != 12 or len(share) < 16:
            raise ValueError("invalid compiled leaf")
        return CompiledLeaf(
            attribute=Attribute.model_validate(data["attribute"]),
            authority_id=data["authority_id"],
            encrypted_share=share,
            nonce=nonce,
        )
    if set(data) != {"node_type", "children", "child_x"} or not data["children"]:
        raise ValueError("invalid compiled branch")
    children = tuple(_decode_node(child) for child in data["children"])
    child_x = tuple(data["child_x"])
    if kind is PolicyNodeType.AND:
        if (
            len(child_x) != len(children)
            or any(
                not isinstance(x, int) or isinstance(x, bool) or x <= 0 for x in child_x
            )
            or len(set(child_x)) != len(child_x)
        ):
            raise ValueError("invalid compiled AND coordinates")
    elif child_x != (1,) * len(children):
        raise ValueError("invalid compiled OR coordinates")
    return CompiledInternal(node_type=kind, children=children, child_x=child_x)
