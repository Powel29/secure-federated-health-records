"""Unit tests for the credential lifecycle and revocation registry (P2-6)."""

from __future__ import annotations

import datetime

import pytest
from authority import (
    AttributeAuthority,
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialRevokedError,
    CredentialStatusError,
    RevocationRegistry,
    issue_credential,
    verify_credential,
)
from contracts import Attribute, CredentialStatus


def test_revocation_registry_record_and_query() -> None:
    """A revocation registry records entries and queries them accurately."""
    registry = RevocationRegistry()
    assert not registry.is_revoked("ser-001")

    now = datetime.datetime.now(datetime.timezone.utc)
    entry = registry.revoke(
        serial="ser-001",
        issuer_id="authority-med",
        reason="License suspended",
        revoked_at=now,
    )

    assert entry.serial == "ser-001"
    assert entry.issuer_id == "authority-med"
    assert entry.reason == "License suspended"
    assert entry.revoked_at == now

    assert registry.is_revoked("ser-001")
    assert not registry.is_revoked("ser-002")

    retrieved = registry.get_entry("ser-001")
    assert retrieved == entry
    assert registry.get_entry("ser-002") is None

    assert registry.all_revoked() == [entry]


def test_authority_revoke_credential_and_status(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """An authority can revoke a credential and query its dynamic lifecycle status."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Initial status is ACTIVE
    assert not authority_med.is_credential_revoked(cred.serial)
    assert authority_med.get_credential_status(cred) == CredentialStatus.ACTIVE

    # Revoke
    authority_med.revoke_credential(cred.serial, reason="Credentials updated")
    assert authority_med.is_credential_revoked(cred.serial)
    assert authority_med.get_credential_status(cred) == CredentialStatus.REVOKED


def test_get_credential_status_temporal_expiry(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """Status is accurately reported as EXPIRED when evaluated past valid_until."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Inside window -> ACTIVE
    assert (
        authority_med.get_credential_status(
            cred, at=valid_from + datetime.timedelta(days=1)
        )
        == CredentialStatus.ACTIVE
    )

    # Past validity window -> EXPIRED
    future = valid_until + datetime.timedelta(days=1)
    assert (
        authority_med.get_credential_status(cred, at=future) == CredentialStatus.EXPIRED
    )

    # Revocation takes precedence over expiry
    authority_med.revoke_credential(cred.serial, reason="Disciplinary action")
    assert (
        authority_med.get_credential_status(cred, at=future) == CredentialStatus.REVOKED
    )


def test_verify_credential_fails_closed_when_revoked(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """verify_credential raises CredentialRevokedError on revoked credentials."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Positive control: unrevoked credential verifies cleanly
    verify_credential(
        cred,
        authority_med.public_key,
        revocation_registry=authority_med.revocation_registry,
    )

    # Revoke and verify rejection
    authority_med.revoke_credential(cred.serial, reason="Left facility")
    with pytest.raises(CredentialRevokedError) as exc_info:
        verify_credential(
            cred,
            authority_med.public_key,
            revocation_registry=authority_med.revocation_registry,
        )
    assert "revoked" in str(exc_info.value).lower()
    # Is also a CredentialStatusError (subclass check)
    assert isinstance(exc_info.value, CredentialStatusError)


def test_get_attribute_key_fails_closed_on_revoked_credential(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """get_attribute_key refuses to release keys for revoked credentials."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Valid credential retrieves key
    key = authority_med.get_attribute_key(cred)
    assert isinstance(key, bytes) and len(key) == 32

    # Revoke credential
    authority_med.revoke_credential(cred.serial)

    # Fails closed
    with pytest.raises(CredentialRevokedError):
        authority_med.get_attribute_key(cred)


def test_get_attribute_key_fails_closed_on_expired_and_not_yet_valid(
    authority_med: AttributeAuthority, valid_window: tuple
) -> None:
    """get_attribute_key fails closed on temporal boundary violations."""
    valid_from, valid_until = valid_window
    cred = issue_credential(
        authority_med,
        "dr-alice",
        Attribute(name="role", value="physician"),
        valid_from,
        valid_until,
    )

    # Before valid_from -> CredentialNotYetValidError
    before_window = valid_from - datetime.timedelta(days=1)
    with pytest.raises(CredentialNotYetValidError):
        authority_med.get_attribute_key(cred, at=before_window)

    # After valid_until -> CredentialExpiredError
    after_window = valid_until + datetime.timedelta(days=1)
    with pytest.raises(CredentialExpiredError):
        authority_med.get_attribute_key(cred, at=after_window)
