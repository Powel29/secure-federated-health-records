"""Tests for the federation's root trust anchor (C5)."""

from __future__ import annotations

from crypto_core import is_ca_certificate, verify_certificate_signature
from identity.root_anchor import RootAnchor, generate_root_anchor


def test_root_anchor_is_self_signed_ca() -> None:
    """The root anchor's certificate is self-signed and carries the CA flag."""
    root = generate_root_anchor()

    verify_certificate_signature(root.certificate, root.public_key)
    assert is_ca_certificate(root.certificate) is True


def test_two_root_anchors_are_independent() -> None:
    """Two generated roots must not share key material."""
    root1 = generate_root_anchor()
    root2 = generate_root_anchor()

    assert root1.public_key.public_numbers() != root2.public_key.public_numbers()


def test_generate_root_anchor_returns_root_anchor_instance() -> None:
    """Sanity check on the returned type's shape."""
    root = generate_root_anchor(common_name="test-root", valid_days=30)

    assert isinstance(root, RootAnchor)
    assert root.certificate.subject.rfc4514_string() == "CN=test-root"
