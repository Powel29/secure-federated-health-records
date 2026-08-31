"""Tests for the record upload / ingest pipeline (P3-14).

Covers:
- Happy-path ingest with encryption, policy, wrapping, and search indexing.
- Owner leaf presence in the authored tree (ADR-0016).
- DEK unwrapping via policy reconstruction (clinician and patient paths).
- Search-token derivation and determinism.
- Validation: missing emergency key when search terms are provided.
- Lifecycle state initialization to GRANTED.
"""

from __future__ import annotations

import datetime

import pytest
from authority.issuance import AttributeAuthority, generate_authority, issue_credential
from contracts import Attribute
from contracts.enums import LifecycleState, PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core.symmetric import generate_key
from policy import reconstruct_root_secret
from records.ingest import IngestResult, ingest_record
from records.service import decrypt_record, unwrap_dek
from search.service import derive_search_token

# --- Fixture helpers ---

MED_AUTHORITY_ID = "authority-med"
NET_AUTHORITY_ID = "authority-net"


def _leaf(name: str, value: str, authority_id: str) -> PolicyTree:
    """Build a single policy leaf node."""
    return PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name=name, value=value),
        authority_id=authority_id,
    )


def _setup_federation() -> tuple[AttributeAuthority, AttributeAuthority, PolicyTree]:
    """Two authorities and a clinical policy ``AND(role:physician, specialty:cardiology)``."""
    med = generate_authority(MED_AUTHORITY_ID, frozenset({"role"}))
    net = generate_authority(NET_AUTHORITY_ID, frozenset({"specialty", "owner"}))
    clinical = PolicyTree(
        node_type=PolicyNodeType.AND,
        children=(
            _leaf("role", "physician", MED_AUTHORITY_ID),
            _leaf("specialty", "cardiology", NET_AUTHORITY_ID),
        ),
    )
    return med, net, clinical


def _authoring_keyring(
    med: AttributeAuthority,
    net: AttributeAuthority,
    patient_id: str,
) -> dict[tuple[str, str, str], bytes]:
    """The compile-time keyring with all leaf keys including the owner leaf."""
    return {
        (MED_AUTHORITY_ID, "role", "physician"): med.attribute_key("role", "physician"),
        (NET_AUTHORITY_ID, "specialty", "cardiology"): net.attribute_key(
            "specialty", "cardiology"
        ),
        (NET_AUTHORITY_ID, "owner", patient_id): net.attribute_key("owner", patient_id),
    }


# --- Tests ---


class TestIngestHappyPath:
    """Core ingest flow: encrypt, policy-attach, wrap, index."""

    def test_ingest_produces_encrypted_record(self) -> None:
        """Ingest produces an encrypted Record with correct metadata."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-200"
        plaintext = b'{"diagnosis": "acute MI", "vitals": {"hr": 110}}'
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=plaintext,
            patient_id=patient_id,
            facility_id="fac-central",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        assert isinstance(result, IngestResult)
        assert result.record.patient_id == patient_id
        assert result.record.facility_id == "fac-central"
        assert result.record.ciphertext != plaintext
        assert len(result.record.nonce) == 12  # GCM nonce

    def test_ingest_record_decryptable_via_root_secret(self) -> None:
        """The DEK recovered from the wrapping decrypts the record payload."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-201"
        plaintext = b"Sensitive health data for round-trip test"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=plaintext,
            patient_id=patient_id,
            facility_id="fac-central",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        # Unwrap DEK using root secret, then decrypt the record.
        dek = unwrap_dek(result.dek_wrapping, result.root_secret)
        decrypted = decrypt_record(result.record, dek)
        assert decrypted == plaintext

    def test_ingest_lifecycle_state_is_granted(self) -> None:
        """Every ingested record starts in the GRANTED lifecycle state."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-202"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"test data",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        assert result.lifecycle_state == LifecycleState.GRANTED


class TestOwnerLeaf:
    """ADR-0016: owner:<patient_id> leaf is baked in at ingest."""

    def test_authored_tree_has_owner_leaf(self) -> None:
        """The authored policy tree contains an OR root with the owner leaf."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-300"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"owner leaf test",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        tree = result.policy_tree
        assert tree.node_type == PolicyNodeType.OR
        assert len(tree.children) == 2

        # One child is the clinical AND, the other is the owner leaf.
        owner_leaves = [
            c
            for c in tree.children
            if c.node_type == PolicyNodeType.LEAF
            and c.attribute is not None
            and c.attribute.name == "owner"
        ]
        assert len(owner_leaves) == 1
        assert owner_leaves[0].attribute.value == patient_id
        assert owner_leaves[0].authority_id == NET_AUTHORITY_ID

    def test_patient_can_reconstruct_via_owner_leaf(self) -> None:
        """A patient holding only the owner credential recovers the root secret."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-301"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"patient access test",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        # The patient holds only their owner key.
        now = datetime.datetime.now(datetime.timezone.utc)
        owner_cred = issue_credential(
            net,
            patient_id,
            Attribute(name="owner", value=patient_id),
            now - datetime.timedelta(days=1),
            now + datetime.timedelta(days=365),
        )
        patient_keyring = {
            (NET_AUTHORITY_ID, "owner", patient_id): net.get_attribute_key(owner_cred),
        }

        recovered = reconstruct_root_secret(result.compiled_policy, patient_keyring)
        assert recovered == result.root_secret


class TestClinicianAccess:
    """Clinician reconstructs via the AND branch of the policy."""

    def test_clinician_can_reconstruct_via_clinical_branch(self) -> None:
        """A clinician holding role AND specialty credentials recovers the root secret."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-400"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"clinician access test",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        now = datetime.datetime.now(datetime.timezone.utc)
        window = (now - datetime.timedelta(days=1), now + datetime.timedelta(days=365))
        role_cred = issue_credential(
            med, "dr-smith", Attribute(name="role", value="physician"), *window
        )
        spec_cred = issue_credential(
            net,
            "dr-smith",
            Attribute(name="specialty", value="cardiology"),
            *window,
        )

        clinician_keyring = {
            (MED_AUTHORITY_ID, "role", "physician"): med.get_attribute_key(role_cred),
            (NET_AUTHORITY_ID, "specialty", "cardiology"): net.get_attribute_key(
                spec_cred
            ),
        }

        recovered = reconstruct_root_secret(result.compiled_policy, clinician_keyring)
        assert recovered == result.root_secret


class TestSearchIndexing:
    """Search-token derivation during ingest."""

    def test_ingest_with_search_terms_produces_tokens(self) -> None:
        """Search terms are HKDF-derived against the emergency key."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-500"
        keyring = _authoring_keyring(med, net, patient_id)
        emergency_key = generate_key(32)

        result = ingest_record(
            plaintext=b"searchable record",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
            search_terms=["cardiac", "troponin"],
            emergency_key=emergency_key,
        )

        assert len(result.search_tokens) == 2
        assert "cardiac" in result.search_tokens
        assert "troponin" in result.search_tokens

    def test_search_tokens_are_deterministic(self) -> None:
        """The same (emergency_key, term) pair produces the same token."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-501"
        keyring = _authoring_keyring(med, net, patient_id)
        emergency_key = generate_key(32)

        result = ingest_record(
            plaintext=b"determinism test",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
            search_terms=["cardiac"],
            emergency_key=emergency_key,
        )

        expected = derive_search_token(emergency_key, "cardiac")
        assert result.search_tokens["cardiac"] == expected

    def test_ingest_without_search_terms_produces_empty_tokens(self) -> None:
        """Omitting search_terms produces an empty token dict."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-502"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"no search terms",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        assert result.search_tokens == {}

    def test_ingest_search_terms_without_emergency_key_raises(self) -> None:
        """Providing search terms without an emergency key raises ValueError."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-503"
        keyring = _authoring_keyring(med, net, patient_id)

        with pytest.raises(ValueError, match="emergency_key is required"):
            ingest_record(
                plaintext=b"should fail",
                patient_id=patient_id,
                facility_id="fac-01",
                owner_authority_id=NET_AUTHORITY_ID,
                clinical_policy=clinical,
                attribute_keyring=keyring,
                search_terms=["cardiac"],
                emergency_key=None,
            )


class TestDEKWrapping:
    """DEK wrapping properties at ingest."""

    def test_wrapping_is_generation_zero(self) -> None:
        """Initial wrapping has generation=0 (first wrap, not a rotation)."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-600"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"wrapping gen test",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        assert result.dek_wrapping.generation == 0

    def test_wrapping_is_bound_to_record_id(self) -> None:
        """The DEK wrapping's record_id matches the encrypted record."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-601"
        keyring = _authoring_keyring(med, net, patient_id)

        result = ingest_record(
            plaintext=b"binding test",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        assert result.dek_wrapping.record_id == result.record.record_id

    def test_different_records_get_different_deks(self) -> None:
        """Two ingest calls produce different DEKs (unique per record)."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-602"
        keyring = _authoring_keyring(med, net, patient_id)

        r1 = ingest_record(
            plaintext=b"record one",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )
        r2 = ingest_record(
            plaintext=b"record two",
            patient_id=patient_id,
            facility_id="fac-01",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
        )

        # Root secrets (and hence DEKs) should differ between records.
        assert r1.root_secret != r2.root_secret
        assert r1.dek_wrapping.wrapped_dek != r2.dek_wrapping.wrapped_dek


class TestEndToEnd:
    """Full pipeline: ingest → policy reconstruct → unwrap DEK → decrypt."""

    def test_full_ingest_to_decrypt_round_trip(self) -> None:
        """End-to-end: ingest a record and decrypt it via the policy engine."""
        med, net, clinical = _setup_federation()
        patient_id = "pat-700"
        keyring = _authoring_keyring(med, net, patient_id)
        emergency_key = generate_key(32)
        plaintext = b'{"test": "full end-to-end ingest pipeline"}'

        result = ingest_record(
            plaintext=plaintext,
            patient_id=patient_id,
            facility_id="fac-central",
            owner_authority_id=NET_AUTHORITY_ID,
            clinical_policy=clinical,
            attribute_keyring=keyring,
            search_terms=["test", "pipeline"],
            emergency_key=emergency_key,
        )

        # Clinician path: issue credentials, reconstruct, unwrap, decrypt.
        now = datetime.datetime.now(datetime.timezone.utc)
        window = (now - datetime.timedelta(days=1), now + datetime.timedelta(days=365))
        role_cred = issue_credential(
            med, "dr-full", Attribute(name="role", value="physician"), *window
        )
        spec_cred = issue_credential(
            net, "dr-full", Attribute(name="specialty", value="cardiology"), *window
        )
        clinician_keyring = {
            (MED_AUTHORITY_ID, "role", "physician"): med.get_attribute_key(role_cred),
            (NET_AUTHORITY_ID, "specialty", "cardiology"): net.get_attribute_key(
                spec_cred
            ),
        }

        root_secret = reconstruct_root_secret(
            result.compiled_policy, clinician_keyring
        )
        dek = unwrap_dek(result.dek_wrapping, root_secret)
        decrypted = decrypt_record(result.record, dek)
        assert decrypted == plaintext

        # Search tokens were indexed.
        assert len(result.search_tokens) == 2
        assert result.lifecycle_state == LifecycleState.GRANTED
