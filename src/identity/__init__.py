"""The federated PKI: root trust anchor, facility CAs, clinician certs (C5).

ARCHITECTURE.md §2 C5: "This is what lets an out-of-network clinician be
verified at all." One shared root (ADR-0019); facility CAs and attribute
authority certificates chain to it; clinician certificates chain through their
enrolling facility's CA. See ``chain.py`` for how a chain is validated and
``trust_registry.py`` for the federation-wide lookup a facility node uses.
"""

from __future__ import annotations

from identity.certificates import (
    issue_authority_certificate,
    issue_certificate,
    issue_clinician_certificate,
    issue_facility_ca_certificate,
)
from identity.chain import validate_chain
from identity.exceptions import ChainValidationError, UnknownFacilityError
from identity.root_anchor import RootAnchor, generate_root_anchor
from identity.trust_registry import TrustRegistry

__all__ = [
    "ChainValidationError",
    "RootAnchor",
    "TrustRegistry",
    "UnknownFacilityError",
    "generate_root_anchor",
    "issue_authority_certificate",
    "issue_certificate",
    "issue_clinician_certificate",
    "issue_facility_ca_certificate",
    "validate_chain",
]
