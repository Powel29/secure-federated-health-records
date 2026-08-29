"""Tests for binding an attribute authority's key to the shared root (C6 <- C5)."""

from __future__ import annotations

from authority.certification import certify_authority
from authority.issuance import AttributeAuthority, generate_authority
from crypto_core import is_ca_certificate, verify_certificate_signature
from identity.root_anchor import RootAnchor, generate_root_anchor


def test_authority_certificate_chains_to_root() -> None:
    """An authority's certificate verifies against the root that issued it."""
    root: RootAnchor = generate_root_anchor()
    authority: AttributeAuthority = generate_authority(
        "authority-med", frozenset({"role"})
    )

    cert = certify_authority(root, authority)

    verify_certificate_signature(cert, root.public_key)
    assert is_ca_certificate(cert) is False
    assert cert.subject.rfc4514_string() == "CN=authority-med"
