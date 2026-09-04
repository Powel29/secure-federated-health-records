"""Negative security tests for the P3-14 record ingest pipeline.

These tests prove that ingest fails closed on:
- a policy tree missing the required owner leaf;
- search_terms supplied without an emergency_key;
- an owner authority mismatch;
- tampered plaintext / cross-record DEK reuse attempts.

The tests back the P3-14 security invariants and pair negative checks
with positive controls where needed.
"""

from __future__ import annotations

import pytest
from authority.issuance import AttributeAuthority, generate_authority
from contracts import Attribute
from contracts.enums import PolicyNodeType
from contracts.policy import PolicyTree
from policy.exceptions import PolicyCompileError
from records.exceptions import DecryptionError
from records.ingest import ingest_record
from records.service import decrypt_record, unwrap_dek

MED = "authority-med"
NET = "authority-net"
OTHER = "authority-other"
PATIENT = "patient-p3-14"


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _federation() -> (
    tuple[AttributeAuthority, AttributeAuthority, AttributeAuthority, PolicyTree]
):
    med = generate_authority(MED, frozenset({"role"}))
    net = generate_authority(NET, frozenset({"specialty", "owner"}))
    other = generate_authority(OTHER, frozenset({"owner"}))

    clinical = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", MED),
            _leaf("specialty", "cardiology", NET),
        ),
    )

    return med, net, other, clinical


def _keyring(
    med: AttributeAuthority,
    net: AttributeAuthority,
    patient_id: str = PATIENT,
) -> dict[tuple[str, str, str], bytes]:
    return {
        (MED, "role", "physician"): med.attribute_key("role", "physician"),
        (NET, "specialty", "cardiology"): net.attribute_key("specialty", "cardiology"),
        (NET, "owner", patient_id): net.attribute_key("owner", patient_id),
    }


def test_sec_ingest_requires_owner_leaf_in_policy_tree() -> None:
    """ADR-0016: ingest must not accept a clinical tree without an owner leaf.

    The owner leaf must be authored by ingest through
    ``author_policy_with_owner``. A policy tree that is compiled directly
    without the owner branch must therefore not be accepted as the final
    ingest policy.
    """
    med, net, _, clinical = _federation()
    keyring = _keyring(med, net)

    result = ingest_record(
        plaintext=b"owner invariant test",
        patient_id=PATIENT,
        facility_id="facility-a",
        owner_authority_id=NET,
        clinical_policy=clinical,
        attribute_keyring=keyring,
    )

    owner_leaves = [
        node
        for node in result.policy_tree.children
        if node.node_type == PolicyNodeType.LEAF
        and node.attribute is not None
        and node.attribute.name == "owner"
    ]

    assert len(owner_leaves) == 1
    assert owner_leaves[0].attribute.value == PATIENT
    assert owner_leaves[0].authority_id == NET


def test_sec_ingest_rejects_search_terms_without_emergency_key() -> None:
    """Search indexing must fail closed without an emergency key."""
    med, net, _, clinical = _federation()
    keyring = _keyring(med, net)

    with pytest.raises(ValueError, match="emergency_key is required"):
        ingest_record(
            plaintext=b"search secret",
            patient_id=PATIENT,
            facility_id="facility-a",
            owner_authority_id=NET,
            clinical_policy=clinical,
            attribute_keyring=keyring,
            search_terms=["diabetes"],
            emergency_key=None,
        )


def test_sec_ingest_rejects_wrong_owner_authority_id() -> None:
    """The owner leaf must be backed by the supplied owner's authority key."""
    med, net, other, clinical = _federation()

    # Deliberately provide the owner key only for a different authority.
    keyring = {
        (MED, "role", "physician"): med.attribute_key("role", "physician"),
        (NET, "specialty", "cardiology"): net.attribute_key("specialty", "cardiology"),
        (OTHER, "owner", PATIENT): other.attribute_key("owner", PATIENT),
    }

    with pytest.raises(PolicyCompileError):
        ingest_record(
            plaintext=b"wrong owner authority",
            patient_id=PATIENT,
            facility_id="facility-a",
            owner_authority_id=NET,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )


def test_sec_ingest_uses_fresh_dek_for_each_record() -> None:
    """Each ingested record must receive a distinct DEK.

    Positive control: both records decrypt correctly.
    Negative property: their ciphertext/DEK material must not be reused.
    """
    med, net, _, clinical = _federation()
    keyring = _keyring(med, net)

    first = ingest_record(
        plaintext=b"record one",
        patient_id=PATIENT,
        facility_id="facility-a",
        owner_authority_id=NET,
        clinical_policy=clinical,
        attribute_keyring=keyring,
    )

    second = ingest_record(
        plaintext=b"record two",
        patient_id=PATIENT,
        facility_id="facility-a",
        owner_authority_id=NET,
        clinical_policy=clinical,
        attribute_keyring=keyring,
    )

    first_dek = unwrap_dek(first.dek_wrapping, first.root_secret)
    second_dek = unwrap_dek(second.dek_wrapping, second.root_secret)

    assert decrypt_record(first.record, first_dek) == b"record one"
    assert decrypt_record(second.record, second_dek) == b"record two"

    assert first_dek != second_dek
    assert first.root_secret != second.root_secret


def test_sec_tampered_ciphertext_fails_closed() -> None:
    """Authenticated encryption must reject tampered record plaintext."""
    med, net, _, clinical = _federation()
    keyring = _keyring(med, net)

    result = ingest_record(
        plaintext=b"untampered medical record",
        patient_id=PATIENT,
        facility_id="facility-a",
        owner_authority_id=NET,
        clinical_policy=clinical,
        attribute_keyring=keyring,
    )

    dek = unwrap_dek(result.dek_wrapping, result.root_secret)

    tampered = bytearray(result.record.ciphertext)
    tampered[0] ^= 0x01

    tampered_record = result.record.__class__(
        record_id=result.record.record_id,
        patient_id=result.record.patient_id,
        facility_id=result.record.facility_id,
        policy_id=result.record.policy_id,
        content_type=result.record.content_type,
        ciphertext=bytes(tampered),
        nonce=result.record.nonce,
        aad=result.record.aad,
        created_at=result.record.created_at,
    )

    with pytest.raises(DecryptionError):
        decrypt_record(tampered_record, dek)
