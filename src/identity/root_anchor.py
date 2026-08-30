"""The federation's single shared trust root (C5, ARCHITECTURE.md §7 step 1).

P0-7 / ADR-0019 fix the federation at two facilities and one shared root; every
facility CA and every attribute authority certificate chains back to this one
anchor, which is what makes an out-of-network clinician's certificate
verifiable at a facility that never enrolled them (ARCHITECTURE.md §5 "Cross-
facility break-glass" step 1).
"""

from __future__ import annotations

from dataclasses import dataclass

from crypto_core import build_certificate, generate_ec_keypair
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import Certificate

DEFAULT_ROOT_VALID_DAYS = 3650  # a decade -- this is the anchor, not a leaf cert
DEFAULT_ROOT_COMMON_NAME = "federation-root"


@dataclass(frozen=True)
class RootAnchor:
    """The federation root: a self-signed keypair and its own certificate.

    Only the bootstrap process holds ``private_key``; every other component
    only ever needs ``certificate`` (to extract the trusted public key) or the
    public key itself, never the private key (ARCHITECTURE.md §7 step 1).
    """

    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    certificate: Certificate


def generate_root_anchor(
    common_name: str = DEFAULT_ROOT_COMMON_NAME,
    valid_days: int = DEFAULT_ROOT_VALID_DAYS,
) -> RootAnchor:
    """Generate the federation's root trust anchor: a self-signed CA certificate.

    Args:
        common_name: CN for the root certificate's subject and issuer.
        valid_days: Validity window length in days, starting now.

    Returns:
        A fresh :class:`RootAnchor`.

    Security property:
        The root's private key never leaves this object; it is the sole basis
        for every trust decision downstream (facility CAs, authority certs,
        clinician certs all chain to it).
    """
    private_key, public_key = generate_ec_keypair()
    certificate = build_certificate(
        subject_public_key=public_key,
        subject_common_name=common_name,
        issuer_private_key=private_key,
        issuer_common_name=common_name,
        valid_days=valid_days,
        is_ca=True,
    )
    return RootAnchor(
        private_key=private_key, public_key=public_key, certificate=certificate
    )
