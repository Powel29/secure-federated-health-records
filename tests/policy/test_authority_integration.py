"""End-to-end: authority-issued attribute keys drive the policy engine (P2-2 + P2-3).

Proves the P2-3 engine reconstructs against *real* attribute keys minted by the
`authority` module (ARCHITECTURE.md §3, §8 C6; ADR-0026) rather than test-conjured
ones -- the credential lifecycle gate and the cryptographic access gate connected.
"""

from __future__ import annotations

import datetime

import pytest
from authority.issuance import AttributeAuthority, generate_authority, issue_credential
from contracts import Attribute, AttributeCredential
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import generate_key
from policy import (
    author_policy_with_owner,
    compile_policy,
    reconstruct_root_secret,
)
from policy.exceptions import PolicyDeniedError

MED = "authority-med"
NET = "authority-net"


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _federation() -> tuple[AttributeAuthority, AttributeAuthority, PolicyTree]:
    """Two authorities and the tree ``(role AND specialty) OR owner:patient-1``."""
    med = generate_authority(MED, frozenset({"role"}))
    net = generate_authority(NET, frozenset({"specialty", "owner"}))
    clinical = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", MED),
            _leaf("specialty", "cardiology", NET),
        ),
    )
    tree = author_policy_with_owner(clinical, "patient-1", NET)
    return med, net, tree


def _authoring_keyring(
    med: AttributeAuthority, net: AttributeAuthority
) -> dict[tuple[str, str, str], bytes]:
    """The compile-side keyring: each owning authority's key for each leaf."""
    return {
        (MED, "role", "physician"): med.attribute_key("role", "physician"),
        (NET, "specialty", "cardiology"): net.attribute_key("specialty", "cardiology"),
        (NET, "owner", "patient-1"): net.attribute_key("owner", "patient-1"),
    }


def _holder_keyring(
    *pairs: tuple[AttributeAuthority, AttributeCredential],
) -> dict[tuple[str, str, str], bytes]:
    """What a holder assembles: a key per credential, gated by get_attribute_key."""
    ring: dict[tuple[str, str, str], bytes] = {}
    for authority, credential in pairs:
        key = authority.get_attribute_key(credential)
        ring[
            (
                credential.issuer_id,
                credential.attribute.name,
                credential.attribute.value,
            )
        ] = key
    return ring


def test_clinician_reconstructs_with_authority_issued_keys() -> None:
    med, net, tree = _federation()
    root_secret = generate_key()
    compiled = compile_policy(tree, root_secret, _authoring_keyring(med, net))

    now = datetime.datetime.now(datetime.timezone.utc)
    window = (now - datetime.timedelta(days=1), now + datetime.timedelta(days=365))
    role_cred = issue_credential(
        med, "dr-jane", Attribute(name="role", value="physician"), *window
    )
    spec_cred = issue_credential(
        net, "dr-jane", Attribute(name="specialty", value="cardiology"), *window
    )

    holder = _holder_keyring((med, role_cred), (net, spec_cred))
    assert reconstruct_root_secret(compiled, holder) == root_secret


def test_patient_reconstructs_with_authority_issued_owner_key() -> None:
    med, net, tree = _federation()
    root_secret = generate_key()
    compiled = compile_policy(tree, root_secret, _authoring_keyring(med, net))

    now = datetime.datetime.now(datetime.timezone.utc)
    owner_cred = issue_credential(
        net,
        "patient-1",
        Attribute(name="owner", value="patient-1"),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )
    holder = _holder_keyring((net, owner_cred))
    assert reconstruct_root_secret(compiled, holder) == root_secret


def test_expired_credential_denies_reconstruction_end_to_end() -> None:
    """An expired specialty credential yields no key, so the AND cannot be met."""
    med, net, tree = _federation()
    root_secret = generate_key()
    compiled = compile_policy(tree, root_secret, _authoring_keyring(med, net))

    now = datetime.datetime.now(datetime.timezone.utc)
    role_cred = issue_credential(
        med,
        "dr-jane",
        Attribute(name="role", value="physician"),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )
    expired_spec = issue_credential(
        net,
        "dr-jane",
        Attribute(name="specialty", value="cardiology"),
        now - datetime.timedelta(days=365),
        now - datetime.timedelta(days=1),
    )

    # The holder cannot even obtain the specialty key: the lifecycle gate fires.
    with pytest.raises(PolicyDeniedError):
        holder = {
            (MED, "role", "physician"): med.get_attribute_key(role_cred),
        }
        # specialty key never obtained -> AND unsatisfied -> denied.
        reconstruct_root_secret(compiled, holder)

    # And obtaining it directly is itself refused.
    from authority.exceptions import CredentialExpiredError

    with pytest.raises(CredentialExpiredError):
        net.get_attribute_key(expired_spec)
