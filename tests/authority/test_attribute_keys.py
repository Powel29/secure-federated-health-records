"""Tests for attribute key material issued by an authority (C6, P2-2 / ADR-0026).

The policy engine seals each leaf to the owning authority's attribute key; these
cover that the authority mints one stable key per attribute (authoring side) and
only releases it to a holder whose credential verifies (holder side).
"""

from __future__ import annotations

import datetime

import pytest
from authority.exceptions import (
    CredentialExpiredError,
    UnauthorizedAttributeError,
)
from authority.issuance import (
    AttributeAuthority,
    generate_authority,
    issue_credential,
)
from contracts import Attribute
from crypto_core import InvalidSignatureError

MED = "authority-med"


def _authority() -> AttributeAuthority:
    return generate_authority(MED, frozenset({"role"}))


def test_attribute_key_is_stable_per_attribute() -> None:
    """The same name:value yields the same key; different values differ."""
    authority = _authority()
    key1 = authority.attribute_key("role", "physician")
    assert authority.attribute_key("role", "physician") == key1
    assert authority.attribute_key("role", "nurse") != key1
    assert len(key1) == 32


def test_attribute_key_refused_outside_namespace() -> None:
    """An authority cannot mint key material for an attribute it does not own."""
    authority = _authority()
    with pytest.raises(UnauthorizedAttributeError):
        authority.attribute_key("specialty", "cardiology")


def test_get_attribute_key_releases_on_valid_credential() -> None:
    """A holder with a valid credential gets exactly the leaf's authoring key."""
    authority = _authority()
    now = datetime.datetime.now(datetime.timezone.utc)
    cred = issue_credential(
        authority,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )
    released = authority.get_attribute_key(cred)
    assert released == authority.attribute_key("role", "physician")


def test_get_attribute_key_denied_for_expired_credential() -> None:
    """An expired credential extracts no key (lifecycle gate meets key release)."""
    authority = _authority()
    now = datetime.datetime.now(datetime.timezone.utc)
    expired = issue_credential(
        authority,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        now - datetime.timedelta(days=365),
        now - datetime.timedelta(days=1),
    )
    with pytest.raises(CredentialExpiredError):
        authority.get_attribute_key(expired)


def test_get_attribute_key_denied_for_forged_credential() -> None:
    """A tampered credential yields no key -- verification runs before release."""
    authority = _authority()
    now = datetime.datetime.now(datetime.timezone.utc)
    cred = issue_credential(
        authority,
        "dr-jane-doe",
        Attribute(name="role", value="physician"),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )
    forged = cred.model_copy(update={"subject_id": "dr-attacker"})
    with pytest.raises(InvalidSignatureError):
        authority.get_attribute_key(forged)


def test_get_attribute_key_denied_for_other_authority_credential() -> None:
    """A key is only released for credentials this authority itself issued."""
    med = _authority()
    net = generate_authority("authority-net", frozenset({"specialty"}))
    now = datetime.datetime.now(datetime.timezone.utc)
    net_cred = issue_credential(
        net,
        "dr-jane-doe",
        Attribute(name="specialty", value="cardiology"),
        now - datetime.timedelta(days=1),
        now + datetime.timedelta(days=365),
    )
    with pytest.raises(UnauthorizedAttributeError):
        med.get_attribute_key(net_cred)
