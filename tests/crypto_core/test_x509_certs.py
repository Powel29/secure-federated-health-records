"""Tests for X.509 certificate primitives in crypto_core (C1)."""

from __future__ import annotations

import datetime

import pytest
from crypto_core.asymmetric import generate_ec_keypair
from crypto_core.exceptions import (
    CertificateExpiredError,
    InvalidSignatureError,
    KeyFormatError,
)
from crypto_core.x509_certs import (
    build_certificate,
    certificate_from_pem,
    certificate_public_key,
    certificate_to_pem,
    check_certificate_validity_window,
    is_ca_certificate,
    verify_certificate_signature,
)


def test_self_signed_certificate_verifies_against_its_own_key() -> None:
    """A self-signed root certificate verifies against its own public key."""
    sk, pk = generate_ec_keypair()
    cert = build_certificate(
        subject_public_key=pk,
        subject_common_name="root",
        issuer_private_key=sk,
        issuer_common_name="root",
        valid_days=3650,
        is_ca=True,
    )

    verify_certificate_signature(cert, pk)
    assert is_ca_certificate(cert) is True


def test_issued_certificate_verifies_against_issuer_key() -> None:
    """A certificate signed by an issuer verifies against the issuer's public key."""
    issuer_sk, issuer_pk = generate_ec_keypair()
    subject_sk, subject_pk = generate_ec_keypair()
    issuer_cert = build_certificate(
        subject_public_key=issuer_pk,
        subject_common_name="issuer",
        issuer_private_key=issuer_sk,
        issuer_common_name="issuer",
        valid_days=3650,
        is_ca=True,
    )
    leaf_cert = build_certificate(
        subject_public_key=subject_pk,
        subject_common_name="leaf",
        issuer_private_key=issuer_sk,
        issuer_common_name=issuer_cert.subject.rfc4514_string(),
        valid_days=365,
        is_ca=False,
    )

    verify_certificate_signature(leaf_cert, issuer_pk)
    assert is_ca_certificate(leaf_cert) is False
    assert (
        certificate_public_key(leaf_cert).public_numbers()
        == subject_pk.public_numbers()
    )


def test_certificate_signed_by_wrong_key_rejected() -> None:
    """Verifying against a key that did not sign the certificate must fail."""
    issuer_sk, _ = generate_ec_keypair()
    _, wrong_pk = generate_ec_keypair()
    _, subject_pk = generate_ec_keypair()

    cert = build_certificate(
        subject_public_key=subject_pk,
        subject_common_name="leaf",
        issuer_private_key=issuer_sk,
        issuer_common_name="issuer",
        valid_days=365,
    )

    with pytest.raises(InvalidSignatureError):
        verify_certificate_signature(cert, wrong_pk)


def test_certificate_validity_window_rejects_out_of_range_time() -> None:
    """Checking the validity window outside its bounds must fail closed."""
    sk, pk = generate_ec_keypair()
    cert = build_certificate(
        subject_public_key=pk,
        subject_common_name="root",
        issuer_private_key=sk,
        issuer_common_name="root",
        valid_days=1,
        is_ca=True,
    )

    check_certificate_validity_window(cert)  # within window, must not raise

    far_future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=10
    )
    with pytest.raises(CertificateExpiredError):
        check_certificate_validity_window(cert, at=far_future)

    far_past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        days=10
    )
    with pytest.raises(CertificateExpiredError):
        check_certificate_validity_window(cert, at=far_past)


def test_certificate_pem_round_trip() -> None:
    """PEM export and import must preserve the certificate exactly."""
    sk, pk = generate_ec_keypair()
    cert = build_certificate(
        subject_public_key=pk,
        subject_common_name="root",
        issuer_private_key=sk,
        issuer_common_name="root",
        valid_days=3650,
        is_ca=True,
    )

    reloaded = certificate_from_pem(certificate_to_pem(cert))
    assert reloaded == cert


def test_invalid_certificate_pem_raises_key_format_error() -> None:
    """Malformed PEM bytes must raise KeyFormatError, not crash uncaught."""
    with pytest.raises(KeyFormatError):
        certificate_from_pem(b"not-a-certificate")
