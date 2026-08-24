"""Tests for policy engine stub (C7)."""

from __future__ import annotations

import pytest
from contracts.base import Attribute
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core.symmetric import generate_key
from policy.exceptions import PolicyDeniedError
from policy.stub import evaluate_and_unwrap_stub, evaluate_policy


def test_leaf_policy_satisfied_and_denied() -> None:
    """Leaf node requires exact matching attribute."""
    leaf = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="role", value="physician"),
        authority_id="auth-hospital-a",
    )

    assert evaluate_policy(leaf, {("role", "physician")}) is True
    assert evaluate_policy(leaf, {("role", "nurse")}) is False
    assert evaluate_policy(leaf, set()) is False


def test_and_policy_tree() -> None:
    """AND node requires all children to evaluate to True."""
    leaf1 = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="role", value="physician"),
        authority_id="auth-a",
    )
    leaf2 = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="specialty", value="cardiology"),
        authority_id="auth-b",
    )
    and_tree = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(leaf1, leaf2),
    )

    # Both attributes present -> True
    assert (
        evaluate_policy(
            and_tree,
            {("role", "physician"), ("specialty", "cardiology")},
        )
        is True
    )

    # Only one attribute present -> False
    assert evaluate_policy(and_tree, {("role", "physician")}) is False
    assert evaluate_policy(and_tree, {("specialty", "cardiology")}) is False


def test_or_policy_tree_with_owner_attribute() -> None:
    """OR node with clinical policy and patient owner attribute (ADR-0016)."""
    clinical_leaf = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="role", value="doctor"),
        authority_id="auth-med-council",
    )
    patient_leaf = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="owner", value="pat-100"),
        authority_id="auth-home-node",
    )
    or_tree = PolicyTree(
        node_type=PolicyNodeType.OR,
        children=(clinical_leaf, patient_leaf),
    )

    # Doctor access -> True
    assert evaluate_policy(or_tree, {("role", "doctor")}) is True

    # Patient self-access -> True
    assert evaluate_policy(or_tree, {("owner", "pat-100")}) is True

    # Another patient -> False
    assert evaluate_policy(or_tree, {("owner", "pat-999")}) is False


def test_evaluate_and_unwrap_stub_fails_closed() -> None:
    """evaluate_and_unwrap_stub must raise PolicyDeniedError when policy fails."""
    tree = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="department", value="emergency"),
        authority_id="auth-main",
    )
    expected_root_key = generate_key(32)

    # Satisfied
    recovered = evaluate_and_unwrap_stub(
        tree,
        {("department", "emergency")},
        expected_root_key,
    )
    assert recovered == expected_root_key

    # Denied
    with pytest.raises(PolicyDeniedError):
        evaluate_and_unwrap_stub(
            tree,
            {("department", "radiology")},
            expected_root_key,
        )
