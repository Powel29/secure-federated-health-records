"""Tests for attribute credential issuance and verification (C6)."""

from __future__ import annotations

import datetime

import pytest
from authority.exceptions import (
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialStatusError,
    UnauthorizedAttributeError,
)
from authority.issuance import (
    AttributeAuthority,
    _signing_payload,
    issue_credential,
    issue_owner_credential,
    verify_credential,
)
from authority.revocation import RevocationRegistry
from contracts import Attribute, AttributeCredential, CredentialStatus
from crypto_core import InvalidSignatureError, sign


def test_issued_credential_verifies_against_issuer_key(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """A credential issued by an authority verifies against the issuer's public key."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    verify_credential(
        cred, authority_med.public_key, revocation_registry=RevocationRegistry()
    )
    assert cred.status == CredentialStatus.ACTIVE
    assert cred.issuer_id == "authority-med"


def test_two_independent_authorities_issue_valid_credentials(
    authority_med: AttributeAuthority,
    authority_net: AttributeAuthority,
    valid_window: tuple,
) -> None:
    """P2-2 exit criterion: two independent authorities each issue valid credentials."""
    valid_from, valid_until = valid_window
    med_cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )
    net_cred = issue_credential(
        authority_net,
        "dr-jane-doe",
        Attribute(name="specialty", value="cardiology"),
        valid_from,
        valid_until,
    )

    verify_credential(
        med_cred, authority_med.public_key, revocation_registry=RevocationRegistry()
    )
    verify_credential(
        net_cred, authority_net.public_key, revocation_registry=RevocationRegistry()
    )


def test_owner_credential_issued_to_patient(
    authority_net: AttributeAuthority, valid_window: tuple
) -> None:
    """ADR-0016: the home authority issues a patient their own owner attribute."""
    valid_from, valid_until = valid_window
    cred = issue_owner_credential(authority_net, "patient-123", valid_from, valid_until)

    verify_credential(
        cred, authority_net.public_key, revocation_registry=RevocationRegistry()
    )
    assert cred.subject_id == "patient-123"
    assert cred.attribute == Attribute(name="owner", value="patient-123")


def test_authority_cannot_issue_outside_owned_namespace(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """authority-med owns role:*, not specialty:* -- issuing outside it is refused.

    Security property: no single authority can mint attributes belonging to
    another authority's namespace (ADR-0019), which is what makes the
    multi-authority model meaningful rather than cosmetic.
    """
    valid_from, valid_until = valid_window
    with pytest.raises(UnauthorizedAttributeError):
        issue_credential(
            authority_med,
            "dr-jane-doe",
            Attribute(name="specialty", value="cardiology"),
            valid_from,
            valid_until,
        )


def test_forged_credential_rejected(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """P2-2 exit criterion: a forged credential is rejected.

    A credential tampered after issuance (subject swapped) must fail
    signature verification -- the attacker cannot silently reassign who a
    credential was issued to.
    """
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )
    forged = cred.model_copy(update={"subject_id": "dr-attacker"})

    with pytest.raises(InvalidSignatureError):
        verify_credential(
            forged, authority_med.public_key, revocation_registry=RevocationRegistry()
        )


def test_credential_verified_against_wrong_authority_key_rejected(
    authority_med: AttributeAuthority,
    authority_net: AttributeAuthority,
    valid_window: tuple,
) -> None:
    """A credential issued by one authority must not verify under another's key."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    with pytest.raises(InvalidSignatureError):
        verify_credential(
            cred, authority_net.public_key, revocation_registry=RevocationRegistry()
        )


def test_credential_not_yet_valid_rejected(authority_med: AttributeAuthority) -> None:
    """A credential checked before its valid_from must fail closed."""
    now = datetime.datetime.now(datetime.timezone.utc)
    future_start = now + datetime.timedelta(days=10)
    future_end = now + datetime.timedelta(days=365)
    cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        future_start,
        future_end,
    )

    with pytest.raises(CredentialNotYetValidError):
        verify_credential(
            cred,
            authority_med.public_key,
            at=now,
            revocation_registry=RevocationRegistry(),
        )


def test_expired_credential_rejected(authority_med: AttributeAuthority) -> None:
    """P2-2 lifecycle field: an expired credential fails validation."""
    now = datetime.datetime.now(datetime.timezone.utc)
    past_start = now - datetime.timedelta(days=365)
    past_end = now - datetime.timedelta(days=1)
    cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        past_start,
        past_end,
    )

    with pytest.raises(CredentialExpiredError):
        verify_credential(
            cred,
            authority_med.public_key,
            at=now,
            revocation_registry=RevocationRegistry(),
        )


def test_tampering_status_after_issuance_breaks_signature(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """Status is bound into the signature, so it cannot be flipped without re-signing.

    Full revocation-registry semantics (an issuer marking a live credential
    revoked) land with P2-6; here we only prove that mutating a credential's
    status without the issuer's key is caught as forgery, not silently allowed.
    """
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )
    tampered = cred.model_copy(update={"status": CredentialStatus.REVOKED})

    with pytest.raises(InvalidSignatureError):
        verify_credential(
            tampered, authority_med.public_key, revocation_registry=RevocationRegistry()
        )


def test_genuinely_revoked_credential_rejected_by_status_check(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """A properly re-signed REVOKED credential fails the explicit status check.

    Distinguishes the status check from signature verification: this
    credential's signature is fully valid for its (REVOKED) contents, so only
    the status gate stops it.
    """
    valid_from, valid_until = valid_window
    attribute = Attribute(name="role", value="physician")
    payload = _signing_payload(
        serial="revoked-test-serial",
        issuer_id=authority_med.authority_id,
        subject_id="dr-jane-doe",
        attribute=attribute,
        valid_from=valid_from,
        valid_until=valid_until,
        status=CredentialStatus.REVOKED,
    )
    revoked_cred = AttributeCredential(
        serial="revoked-test-serial",
        issuer_id=authority_med.authority_id,
        subject_id="dr-jane-doe",
        attribute=attribute,
        valid_from=valid_from,
        valid_until=valid_until,
        status=CredentialStatus.REVOKED,
        signature=sign(authority_med.private_key, payload),
    )

    with pytest.raises(CredentialStatusError):
        verify_credential(
            revoked_cred,
            authority_med.public_key,
            revocation_registry=RevocationRegistry(),
        )
