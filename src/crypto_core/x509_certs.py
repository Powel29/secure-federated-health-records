"""X.509 certificate primitives on ECDSA P-256 (C1).

This is the single primitive surface for building, signing, and verifying
certificates. The `identity` module (C5) owns the *domain* logic -- what a
root anchor is, how a chain is walked, what "cross-certified" means for this
federation -- but every hazmat-touching operation underneath it lives here,
per CONVENTIONS.md §2 rule 1 (all primitives go through `crypto_core`).

A certificate here is a standard ``cryptography.x509.Certificate``: real
X.509, not a hand-rolled structure -- ARCHITECTURE.md §1 lists X.509 as a
pyca-provided primitive, not one of the three hand-rolled constructions.
"""

from __future__ import annotations

import datetime
import ipaddress

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from crypto_core.exceptions import (
    CertificateExpiredError,
    InvalidSignatureError,
    KeyFormatError,
)


def build_certificate(
    *,
    subject_public_key: ec.EllipticCurvePublicKey,
    subject_common_name: str,
    issuer_private_key: ec.EllipticCurvePrivateKey,
    issuer_common_name: str,
    valid_days: int,
    is_ca: bool = False,
) -> x509.Certificate:
    """Build and sign an X.509 certificate for ``subject_public_key``.

    Self-signing (a root anchor) is the case where ``issuer_private_key`` is
    the private half of ``subject_public_key`` and the two common names match;
    every other call issues a certificate for someone else's key.

    Args:
        subject_public_key: The public key the certificate attests to.
        subject_common_name: CN of the subject (facility id, clinician id, ...).
        issuer_private_key: The signing key -- the issuer's private key.
        issuer_common_name: CN of the issuer.
        valid_days: Validity window length in days, starting now.
        is_ca: Whether the subject may itself sign certificates (BasicConstraints).

    Returns:
        The signed certificate.

    Security property:
        The certificate binds subject identity to subject public key under the
        issuer's signature; ``valid_days`` gives every certificate a bounded
        lifetime (ARCHITECTURE.md §8 credential lifecycle).
    """
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_public_key),
            critical=False,
        )
    )
    return builder.sign(issuer_private_key, hashes.SHA256())


def build_self_signed_tls_cert(
    *,
    signing_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    dns_names: tuple[str, ...] = (),
    ip_addresses: tuple[str, ...] = (),
    valid_days: int = 365,
) -> x509.Certificate:
    """Build a self-signed TLS server certificate with a SubjectAlternativeName.

    For the P4-6 traffic-capture harness only: local, throwaway server certs so
    the federation can be spoken to over TLS while a capture runs. Kept here so
    the hazmat surface stays inside ``crypto_core`` (CONVENTIONS.md §2 rule 1) --
    ``wire`` calls this, it does not touch ``cryptography`` itself.

    Args:
        signing_key: The server's own EC private key (self-signed: subject key
            is this key's public half).
        common_name: CN and the identity the SAN is built around.
        dns_names: DNS SubjectAlternativeName entries (e.g. the service name,
            ``"localhost"``).
        ip_addresses: IP SubjectAlternativeName entries (e.g. ``"127.0.0.1"``).
        valid_days: Bounded validity window in days (ARCHITECTURE.md §8: nothing
            issues forever -- so no far-future certs even for a capture cert).

    Returns:
        The signed certificate.
    """
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)

    san_entries: list[x509.GeneralName] = [x509.DNSName(d) for d in dns_names]
    san_entries.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(signing_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False
        )
    return builder.sign(signing_key, hashes.SHA256())


def verify_certificate_signature(
    cert: x509.Certificate, issuer_public_key: ec.EllipticCurvePublicKey
) -> None:
    """Verify that ``cert`` was signed by ``issuer_public_key``.

    Args:
        cert: The certificate to check.
        issuer_public_key: The purported issuer's public key.

    Raises:
        InvalidSignatureError: The signature does not verify -- a forged or
            mis-issued certificate. Fails closed (CONVENTIONS.md §2 rule 6).

    Security property:
        Authenticity of the subject-to-key binding, anchored to whoever holds
        ``issuer_public_key``.
    """
    try:
        issuer_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    except InvalidSignature as exc:
        raise InvalidSignatureError(
            "certificate signature verification failed"
        ) from exc


def check_certificate_validity_window(
    cert: x509.Certificate, at: datetime.datetime | None = None
) -> None:
    """Check that ``cert`` is within its validity window.

    Args:
        cert: The certificate to check.
        at: The instant to check against; defaults to now (UTC).

    Raises:
        CertificateExpiredError: ``at`` is before ``not_valid_before`` or after
            ``not_valid_after``. Fails closed.

    Security property:
        A credential lifecycle is enforced -- no certificate is trusted forever
        or before it was issued (ARCHITECTURE.md §8).
    """
    now = at if at is not None else datetime.datetime.now(datetime.timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise CertificateExpiredError(
            f"certificate not valid at {now.isoformat()} "
            f"(window {cert.not_valid_before_utc.isoformat()} .. "
            f"{cert.not_valid_after_utc.isoformat()})"
        )


def certificate_public_key(cert: x509.Certificate) -> ec.EllipticCurvePublicKey:
    """Return ``cert``'s public key, typed as an EC public key.

    Raises:
        KeyFormatError: The certificate's key is not an EC key -- this
            federation issues only P-256 certificates.
    """
    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise KeyFormatError(
            f"expected EC public key in certificate, got {type(public_key).__name__}"
        )
    return public_key


def is_ca_certificate(cert: x509.Certificate) -> bool:
    """Return whether ``cert`` carries the CA basic constraint."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return bool(ext.value.ca)


def certificate_to_pem(cert: x509.Certificate) -> bytes:
    """Serialize a certificate to PEM bytes."""
    return cert.public_bytes(serialization.Encoding.PEM)


def certificate_from_pem(pem_bytes: bytes) -> x509.Certificate:
    """Deserialize a certificate from PEM bytes.

    Raises:
        KeyFormatError: The PEM bytes are not a valid certificate.
    """
    try:
        return x509.load_pem_x509_certificate(pem_bytes)
    except Exception as exc:
        raise KeyFormatError(f"Failed to load certificate from PEM: {exc}") from exc
