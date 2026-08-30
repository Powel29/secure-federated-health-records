"""Multi-authority attribute issuance (C6, ARCHITECTURE.md §2).

Each authority (medical council, hospital network) issues signed attribute
credentials that the ``policy`` engine (C7) checks against a record's policy
tree. See ``issuance.py`` for issuance/verification and ``certification.py``
for how an authority's own signing key is bound to the shared root (C5).
"""

from __future__ import annotations

from authority.certification import certify_authority
from authority.exceptions import (
    CredentialExpiredError,
    CredentialNotYetValidError,
    CredentialRevokedError,
    CredentialStatusError,
    UnauthorizedAttributeError,
)
from authority.issuance import (
    AttributeAuthority,
    generate_authority,
    issue_credential,
    issue_owner_credential,
    verify_credential,
)
from authority.revocation import (
    RevocationEntry,
    RevocationRegistry,
)

__all__ = [
    "AttributeAuthority",
    "CredentialExpiredError",
    "CredentialNotYetValidError",
    "CredentialRevokedError",
    "CredentialStatusError",
    "RevocationEntry",
    "RevocationRegistry",
    "UnauthorizedAttributeError",
    "certify_authority",
    "generate_authority",
    "issue_credential",
    "issue_owner_credential",
    "verify_credential",
]
