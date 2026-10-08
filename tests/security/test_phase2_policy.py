"""Negative security tests for the access structure engine (C7, P2-3, CONVENTIONS §5).

These are the evidence the policy engine fails closed: an unsatisfied policy
yields no root secret (not a partial one), leaf authority binding is
cryptographic, tampering is caught, and the ADR-0016 patient path denies a
logged-in patient who lacks the owner attribute. The collusion test documents
the known ADR-0002 limitation so the paper's honesty caveat is backed by a test.
"""

from __future__ import annotations

import dataclasses

import pytest
from contracts.base import Attribute
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import generate_key
from policy import (
    author_policy_with_owner,
    compile_policy,
    reconstruct_root_secret,
    unwrap_dek_via_policy,
)
from policy.exceptions import PolicyDeniedError
from records import wrap_dek
from records.exceptions import UnwrappingError

MED = "authority-med"
NET = "authority-net"


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _and_role_and_specialty() -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", MED),
            _leaf("specialty", "cardiology", NET),
        ),
    )


def _keyring(*entries: tuple[str, str, str]) -> dict[tuple[str, str, str], bytes]:
    return {entry: generate_key() for entry in entries}


def test_sec_missing_one_and_leaf_is_denied_and_leaks_no_secret() -> None:
    """A holder missing one leaf of an AND is denied; no root secret is produced."""
    keyring = _keyring((MED, "role", "physician"), (NET, "specialty", "cardiology"))
    root_secret = generate_key()
    compiled = compile_policy(_and_role_and_specialty(), root_secret, keyring)

    # Holds only the role leaf's key -- the AND cannot be reconstructed.
    holder = {(MED, "role", "physician"): keyring[(MED, "role", "physician")]}
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(compiled, holder)


def test_sec_wrong_attribute_key_does_not_satisfy_leaf() -> None:
    """Holding the attribute name is not enough -- the issued key is required."""
    keyring = _keyring((MED, "role", "physician"), (NET, "specialty", "cardiology"))
    root_secret = generate_key()
    compiled = compile_policy(_and_role_and_specialty(), root_secret, keyring)

    # Correct tuples, but a specialty key that was never the issued one.
    holder = {
        (MED, "role", "physician"): keyring[(MED, "role", "physician")],
        (NET, "specialty", "cardiology"): generate_key(),  # wrong bytes
    }
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(compiled, holder)


def test_sec_leaf_is_bound_to_its_owning_authority() -> None:
    """A key filed under a different authority cannot open a leaf owned by NET."""
    keyring = _keyring((MED, "role", "physician"), (NET, "specialty", "cardiology"))
    root_secret = generate_key()
    compiled = compile_policy(_and_role_and_specialty(), root_secret, keyring)

    # Same name:value and even the right key bytes, but presented as MED's --
    # the leaf's lookup is (NET, specialty, cardiology), so it does not match.
    holder = {
        (MED, "role", "physician"): keyring[(MED, "role", "physician")],
        (MED, "specialty", "cardiology"): keyring[(NET, "specialty", "cardiology")],
    }
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(compiled, holder)


def test_sec_tampered_leaf_ciphertext_fails_closed() -> None:
    """Flipping a byte of a compiled leaf's share denies access, never grants it."""
    keyring = _keyring((MED, "role", "emergency-physician"))
    root_secret = generate_key()
    tree = _leaf("role", "emergency-physician", MED)
    # A single-leaf policy compiles to a bare CompiledLeaf at the root.
    compiled = compile_policy(tree, root_secret, keyring)

    leaf = compiled.root
    corrupted_share = bytes([leaf.encrypted_share[0] ^ 0x01]) + leaf.encrypted_share[1:]
    tampered = dataclasses.replace(
        compiled, root=dataclasses.replace(leaf, encrypted_share=corrupted_share)
    )

    holder = dict(keyring)
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(tampered, holder)


@pytest.mark.claim("C11", level="module")
def test_sec_patient_without_owner_attribute_cannot_unwrap() -> None:
    """ADR-0016 fail-closed: a logged-in patient without the owner key is denied.

    Being identified as the patient (the portal's job) grants nothing; only the
    owner attribute key, held by the home authority, reconstructs the record.
    """
    keyring = _keyring(
        (MED, "role", "physician"),
        (NET, "specialty", "cardiology"),
        (NET, "owner", "patient-1"),
    )
    root_secret = generate_key()
    tree = author_policy_with_owner(_and_role_and_specialty(), "patient-1", NET)
    compiled = compile_policy(tree, root_secret, keyring)

    dek = generate_key()
    wrapping = wrap_dek(
        dek, record_id="rec-1", wrapping_key=root_secret, wrapped_for="pol-1"
    )

    # Positive control: the same patient holding the owner key does unwrap,
    # so the refusal below is the missing key and not a broken fixture.
    owner_only = {(NET, "owner", "patient-1"): keyring[(NET, "owner", "patient-1")]}
    assert unwrap_dek_via_policy(compiled, owner_only, wrapping) == dek

    # "Logged in" but holds no attribute key at all.
    with pytest.raises(PolicyDeniedError):
        unwrap_dek_via_policy(compiled, {}, wrapping)


def test_sec_wrapping_from_a_different_policy_does_not_unwrap() -> None:
    """A satisfied policy still fails to unwrap a DEK sealed under another root."""
    keyring = _keyring((MED, "role", "emergency-physician"))
    root_secret = generate_key()
    compiled = compile_policy(
        _leaf("role", "emergency-physician", MED), root_secret, keyring
    )

    # DEK wrapped under an unrelated secret, not this policy's root.
    other_secret = generate_key()
    dek = generate_key()
    foreign_wrapping = wrap_dek(
        dek, record_id="rec-9", wrapping_key=other_secret, wrapped_for="pol-9"
    )

    with pytest.raises(UnwrappingError):
        unwrap_dek_via_policy(compiled, dict(keyring), foreign_wrapping)


def test_sec_collusion_is_a_documented_limitation_not_a_defended_property() -> None:
    """Two holders pooling keys satisfy an AND neither satisfies alone.

    This is the known, disclosed limitation of the secret-sharing substitute
    (ADR-0002 / PROJECT §5 item 4): it is not collusion-resistant. The test
    asserts the limitation *holds as described* so the paper's honesty caveat is
    evidence-backed, not a claim that this behaviour is desirable.
    """
    keyring = _keyring((MED, "role", "physician"), (NET, "specialty", "cardiology"))
    root_secret = generate_key()
    compiled = compile_policy(_and_role_and_specialty(), root_secret, keyring)

    holder_a = {(MED, "role", "physician"): keyring[(MED, "role", "physician")]}
    holder_b = {
        (NET, "specialty", "cardiology"): keyring[(NET, "specialty", "cardiology")]
    }

    # Neither alone can reconstruct...
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(compiled, holder_a)
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(compiled, holder_b)

    # ...but pooling their keys does. Documented limitation, not a fix.
    pooled = {**holder_a, **holder_b}
    assert reconstruct_root_secret(compiled, pooled) == root_secret
