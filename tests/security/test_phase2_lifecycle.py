"""Negative security tests for credential lifecycle and revocation (P2-6).

Backs the P2-6 exit criterion in WORKFLOW.md: "expired or revoked credentials are
rejected at check time" and the CONVENTIONS §5 negative test requirement:
"an expired or revoked credential fails validation."

Proves that:
1. Revoked credentials fail validation and cannot release attribute keys.
2. Expired credentials fail validation and cannot release attribute keys.
3. Policy reconstruction fails closed when an essential credential is revoked.
4. Patient self-access fails closed if the owner credential is revoked.
"""

from __future__ import annotations

import datetime

import pytest
from authority import (
    CredentialExpiredError,
    CredentialRevokedError,
    generate_authority,
    issue_credential,
    issue_owner_credential,
    verify_credential,
)
from authority.issuance import _signing_payload
from authority.revocation import RevocationRegistry
from contracts import Attribute, AttributeCredential
from contracts.enums import CredentialStatus, PolicyNodeType
from contracts.policy import PolicyTree
from crypto_core import InvalidSignatureError, generate_key, sign
from policy import (
    author_policy_with_owner,
    compile_policy,
    reconstruct_root_secret,
)
from policy.exceptions import PolicyDeniedError


@pytest.mark.claim("C10", level="module")
def test_sec_revoked_credential_fails_validation_and_key_release() -> None:
    """Security property: a revoked credential fails validation and yields no key."""
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=1)
    valid_until = now + datetime.timedelta(days=365)

    authority = generate_authority("authority-med", frozenset({"role"}))
    cred = issue_credential(
        authority,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Positive control: valid credential obtains attribute key
    key = authority.get_attribute_key(cred)
    assert len(key) == 32

    # Authority revokes the credential
    authority.revoke_credential(cred.serial, reason="Suspended license")

    # Negative 1: verify_credential raises CredentialRevokedError
    with pytest.raises(CredentialRevokedError):
        verify_credential(
            cred,
            authority.public_key,
            revocation_registry=authority.revocation_registry,
        )

    # Negative 2: get_attribute_key refuses to release the key
    with pytest.raises(CredentialRevokedError):
        authority.get_attribute_key(cred)


@pytest.mark.claim("C10", level="module")
def test_sec_expired_credential_fails_validation_and_key_release() -> None:
    """Security property: an expired credential fails validation and yields no key."""
    now = datetime.datetime.now(datetime.timezone.utc)
    # Validity window was in the past
    valid_from = now - datetime.timedelta(days=30)
    valid_until = now - datetime.timedelta(days=1)

    authority = generate_authority("authority-med", frozenset({"role"}))
    cred = issue_credential(
        authority,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Positive control: inside its validity window the same credential
    # verifies and releases a key, so the refusal below is the expiry check
    # and not a broken fixture.
    inside_window = valid_from + datetime.timedelta(days=1)
    verify_credential(
        cred,
        authority.public_key,
        at=inside_window,
        revocation_registry=RevocationRegistry(),
    )
    assert len(authority.get_attribute_key(cred, at=inside_window)) == 32

    # Negative: verify_credential raises CredentialExpiredError at check time
    with pytest.raises(CredentialExpiredError):
        verify_credential(
            cred, authority.public_key, at=now, revocation_registry=RevocationRegistry()
        )

    # Negative: get_attribute_key raises CredentialExpiredError
    with pytest.raises(CredentialExpiredError):
        authority.get_attribute_key(cred, at=now)


def test_sec_tampered_revoked_status_fails_signature() -> None:
    """Security property: modifying status field without re-signing fails signature."""
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=1)
    valid_until = now + datetime.timedelta(days=365)

    authority = generate_authority("authority-med", frozenset({"role"}))

    # An authority signs a credential payload whose status is REVOKED
    serial = "ser-revoked-001"
    attr = Attribute(name="role", value="physician")
    payload = _signing_payload(
        serial=serial,
        issuer_id=authority.authority_id,
        subject_id="dr-alice",
        attribute=attr,
        valid_from=valid_from,
        valid_until=valid_until,
        status=CredentialStatus.REVOKED,
    )
    sig = sign(authority.private_key, payload)
    revoked_cred = AttributeCredential(
        serial=serial,
        issuer_id=authority.authority_id,
        subject_id="dr-alice",
        attribute=attr,
        valid_from=valid_from,
        valid_until=valid_until,
        status=CredentialStatus.REVOKED,
        signature=sig,
    )

    # Attacker tampers with the status field from REVOKED -> ACTIVE
    tampered_active = revoked_cred.model_copy(
        update={"status": CredentialStatus.ACTIVE}
    )

    # Signature fails against the original signature over REVOKED
    with pytest.raises(InvalidSignatureError):
        verify_credential(
            tampered_active,
            authority.public_key,
            revocation_registry=RevocationRegistry(),
        )


def test_sec_revoked_attribute_credential_denies_policy_decryption() -> None:
    """Security property: revoking an attribute denies policy-gated key recovery.

    End-to-end integration: A policy requires role:physician. When the clinician's
    credential is valid, they obtain the attribute key and reconstruct the root secret.
    Once their credential is revoked by the authority, key release fails and
    consequently DEK reconstruction fails closed.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=1)
    valid_until = now + datetime.timedelta(days=365)

    med = generate_authority("authority-med", frozenset({"role"}))
    cred = issue_credential(
        med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    tree = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="role", value="physician"),
        authority_id=med.authority_id,
    )

    root_secret = generate_key()
    authoring_keyring = {
        (med.authority_id, "role", "physician"): med.attribute_key("role", "physician")
    }
    compiled = compile_policy(tree, root_secret, authoring_keyring)

    # Positive control: with active credential, root secret reconstructs
    physician_key = med.get_attribute_key(cred)
    holder_keys = {(med.authority_id, "role", "physician"): physician_key}
    assert reconstruct_root_secret(compiled, holder_keys) == root_secret

    # Authority revokes dr-alice's credential
    med.revoke_credential(cred.serial, reason="Privileges revoked")

    # Dr. Alice cannot obtain attribute key from the authority anymore
    with pytest.raises(CredentialRevokedError):
        med.get_attribute_key(cred)

    # Without the key, policy reconstruction fails closed to PolicyDeniedError
    with pytest.raises(PolicyDeniedError):
        reconstruct_root_secret(compiled, {})


@pytest.mark.claim("C11", level="module")
def test_sec_revoked_owner_credential_denies_patient_self_access() -> None:
    """Security property: patient self-access fails if owner credential is revoked."""
    now = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now - datetime.timedelta(days=1)
    valid_until = now + datetime.timedelta(days=365)

    home_auth = generate_authority("authority-net", frozenset({"specialty", "owner"}))
    patient_id = "patient-999"
    owner_cred = issue_owner_credential(home_auth, patient_id, valid_from, valid_until)

    clinical_tree = PolicyTree(
        node_type=PolicyNodeType.LEAF,
        attribute=Attribute(name="specialty", value="cardiology"),
        authority_id="authority-net",
    )
    tree_with_owner = author_policy_with_owner(
        clinical_tree, patient_id, home_auth.authority_id
    )

    root_secret = generate_key()
    authoring_keyring = {
        (home_auth.authority_id, "specialty", "cardiology"): home_auth.attribute_key(
            "specialty", "cardiology"
        ),
        (home_auth.authority_id, "owner", patient_id): home_auth.attribute_key(
            "owner", patient_id
        ),
    }
    compiled = compile_policy(tree_with_owner, root_secret, authoring_keyring)

    # Positive control: patient with active owner credential can reconstruct
    owner_key = home_auth.get_attribute_key(owner_cred)
    holder_keys = {(home_auth.authority_id, "owner", patient_id): owner_key}
    assert reconstruct_root_secret(compiled, holder_keys) == root_secret

    # Patient credential is revoked
    home_auth.revoke_credential(owner_cred.serial, reason="Account locked")

    # Key release is refused
    with pytest.raises(CredentialRevokedError):
        home_auth.get_attribute_key(owner_cred)
