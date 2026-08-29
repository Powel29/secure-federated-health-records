"""Binding an attribute authority's signing key to the shared root (C6 <- C5).

ARCHITECTURE.md §4 dependency map: ``C6 authority <- C1, C5`` -- "issuance
needs certs to sign under." An authority's public key on its own proves
nothing; this is what lets a relying party confirm that a given public key
really belongs to a legitimate, federation-recognised authority, by chaining
its certificate to the root anchor the same way a facility CA or clinician
certificate does.
"""

from __future__ import annotations

from cryptography.x509 import Certificate
from identity.certificates import issue_authority_certificate
from identity.root_anchor import RootAnchor

from authority.issuance import AttributeAuthority


def certify_authority(root: RootAnchor, authority: AttributeAuthority) -> Certificate:
    """Issue ``authority``'s identity certificate, signed by the root anchor.

    Args:
        root: The federation's root anchor.
        authority: The attribute authority to certify.

    Returns:
        The authority's certificate, chaining directly to ``root``.
    """
    return issue_authority_certificate(
        root, authority.authority_id, authority.public_key
    )
