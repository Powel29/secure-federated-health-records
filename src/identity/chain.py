"""Certificate chain validation back to the shared root (C5).

This is what makes an out-of-network clinician's certificate verifiable
(ARCHITECTURE.md §5 "Cross-facility break-glass" step 1; P2-1 exit criterion):
walk from a leaf certificate up through zero or more intermediates to the
federation's trusted root, checking every link's signature, validity window,
and issuer/subject continuity along the way.
"""

from __future__ import annotations

import datetime

from crypto_core import (
    certificate_public_key,
    check_certificate_validity_window,
    is_ca_certificate,
    verify_certificate_signature,
)
from cryptography.x509 import Certificate

from identity.exceptions import ChainValidationError


def validate_chain(
    leaf: Certificate,
    intermediates: list[Certificate],
    trusted_root: Certificate,
    at: datetime.datetime | None = None,
) -> None:
    """Validate that ``leaf`` chains to ``trusted_root`` through ``intermediates``.

    Args:
        leaf: The certificate being presented (e.g. a clinician certificate).
        intermediates: The signing chain from ``leaf``'s issuer up to (but not
            including) the root, in issuance order -- e.g. ``[facility_ca_cert]``.
        trusted_root: The root certificate the caller trusts. Must be byte-
            identical to the root the top of the chain claims to be issued by
            -- a certificate merely claiming ``CN=federation-root`` is not
            enough (that is exactly what a forged chain would also claim).
        at: The instant to check validity windows against; defaults to now.

    Raises:
        InvalidSignatureError: Any link's signature does not verify.
        CertificateExpiredError: Any certificate in the chain is outside its
            validity window.
        ChainValidationError: An intermediate is missing the CA basic
            constraint, an issuer/subject name does not match the next link,
            or the chain's top does not terminate at ``trusted_root``.

    Security property:
        Fails closed at the first broken link -- a chain is either fully valid
        back to the trusted root or it is rejected outright, never partially
        accepted (CONVENTIONS.md §2 rule 6).
    """
    check_certificate_validity_window(leaf, at=at)
    check_certificate_validity_window(trusted_root, at=at)

    chain = [leaf, *intermediates]
    for index, cert in enumerate(chain):
        is_top_of_chain = index == len(chain) - 1
        signer = trusted_root if is_top_of_chain else chain[index + 1]

        if not is_top_of_chain:
            check_certificate_validity_window(signer, at=at)
            if not is_ca_certificate(signer):
                raise ChainValidationError(
                    f"intermediate {signer.subject.rfc4514_string()!r} is not a CA "
                    "certificate; it cannot sign other certificates"
                )

        if cert.issuer != signer.subject:
            raise ChainValidationError(
                f"issuer {cert.issuer.rfc4514_string()!r} of "
                f"{cert.subject.rfc4514_string()!r} does not match subject "
                f"{signer.subject.rfc4514_string()!r} of the next link"
            )

        # Raises InvalidSignatureError on failure -- fails closed on any forged
        # or mis-issued link, including the top link against `trusted_root`.
        verify_certificate_signature(cert, certificate_public_key(signer))
