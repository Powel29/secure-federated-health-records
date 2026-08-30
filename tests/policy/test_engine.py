"""Tests for the real access structure engine (C7, P2-3).

Backs the P2-3 exit criterion: a requester whose attribute keys satisfy the
policy tree reconstructs the root secret and unwraps the record's DEK; the
boolean PDP (``evaluate_policy``) keeps the P1-6 stub's behaviour.
"""

from __future__ import annotations

from contracts.base import Attribute
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import generate_key
from policy import (
    author_policy_with_owner,
    compile_policy,
    evaluate_policy,
    reconstruct_root_secret,
    unwrap_dek_via_policy,
)
from records import wrap_dek

MED = "authority-med"  # owns role:*
NET = "authority-net"  # owns specialty:*, owner:*


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _clinical_policy() -> PolicyTree:
    """``(role:physician AND specialty:cardiology) OR role:emergency-physician``."""
    both = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", MED),
            _leaf("specialty", "cardiology", NET),
        ),
    )
    emergency = _leaf("role", "emergency-physician", MED)
    return PolicyTree(node_type=PolicyNodeType.OR, children=(both, emergency))


def _full_keyring() -> dict[tuple[str, str, str], bytes]:
    """One issued attribute key per attribute the tests reference."""
    entries = [
        (MED, "role", "physician"),
        (NET, "specialty", "cardiology"),
        (MED, "role", "emergency-physician"),
        (NET, "owner", "patient-1"),
    ]
    return {entry: generate_key() for entry in entries}


def _held(keyring: dict, *entries: tuple[str, str, str]) -> dict:
    """The subset of a keyring a particular holder was issued."""
    return {entry: keyring[entry] for entry in entries}


def test_evaluate_policy_boolean_pdp_matches_tree_semantics() -> None:
    tree = _clinical_policy()
    # AND branch satisfied.
    assert evaluate_policy(tree, {("role", "physician"), ("specialty", "cardiology")})
    # OR branch satisfied on its own.
    assert evaluate_policy(tree, {("role", "emergency-physician")})
    # Half of the AND, and nothing on the OR branch: unsatisfied.
    assert not evaluate_policy(tree, {("role", "physician")})
    assert not evaluate_policy(tree, set())


def test_doctor_satisfying_and_branch_reconstructs_root_and_unwraps_dek() -> None:
    keyring = _full_keyring()
    root_secret = generate_key()
    compiled = compile_policy(_clinical_policy(), root_secret, keyring)

    holder = _held(
        keyring, (MED, "role", "physician"), (NET, "specialty", "cardiology")
    )
    assert reconstruct_root_secret(compiled, holder) == root_secret

    # Full path: a DEK wrapped under the root secret is recovered via the policy.
    dek = generate_key()
    wrapping = wrap_dek(
        dek, record_id="rec-1", wrapping_key=root_secret, wrapped_for="pol-1"
    )
    assert unwrap_dek_via_policy(compiled, holder, wrapping) == dek


def test_emergency_physician_satisfies_or_branch_alone() -> None:
    keyring = _full_keyring()
    root_secret = generate_key()
    compiled = compile_policy(_clinical_policy(), root_secret, keyring)

    holder = _held(keyring, (MED, "role", "emergency-physician"))
    assert reconstruct_root_secret(compiled, holder) == root_secret


def test_patient_owner_leaf_reconstructs_own_record() -> None:
    """ADR-0016: a patient holding only owner:<id> reconstructs via the root OR."""
    keyring = _full_keyring()
    root_secret = generate_key()
    tree = author_policy_with_owner(_clinical_policy(), "patient-1", NET)
    compiled = compile_policy(tree, root_secret, keyring)

    holder = _held(keyring, (NET, "owner", "patient-1"))
    assert reconstruct_root_secret(compiled, holder) == root_secret


def test_reconstructed_secret_is_exactly_the_root_secret() -> None:
    """Nested AND/OR splitting round-trips the 32-byte root secret bit-for-bit."""
    keyring = _full_keyring()
    root_secret = generate_key()
    compiled = compile_policy(_clinical_policy(), root_secret, keyring)

    holder = _held(
        keyring, (MED, "role", "physician"), (NET, "specialty", "cardiology")
    )
    recovered = reconstruct_root_secret(compiled, holder)
    assert recovered == root_secret
    assert len(recovered) == len(root_secret) == 32
