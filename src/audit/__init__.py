"""Hash-chained signed audit log + break-glass share custody (C10).

``chain`` implements the ARCHITECTURE.md §2 C10 formula
(``h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)``) and full-chain
verification (P3-3). ``share_custody`` implements "log-before-release": the
audit service's held break-glass share is returned only after its log entry
durably commits (P3-4, ARCHITECTURE.md §5 step 3). ``events`` gives access
denials and federation actions (discovery, PRE re-wrap) a fixed,
minimal-leakage event shape on top of ``chain.append_entry`` (P3-13).
"""

from audit.chain import (
    GENESIS_PREV_HASH,
    append_entry,
    compute_entry_hash,
    create_genesis_entry,
    verify_chain,
    verify_full_chain,
)
from audit.events import (
    DENIED_BY_CONSENT,
    DENIED_BY_CREDENTIAL,
    DENIED_BY_POLICY,
    DENIED_BY_REVOCATION_AUTHZ,
    EVENT_ACCESS_DENIED,
    EVENT_FEDERATION_DISCOVERY,
    EVENT_FEDERATION_REWRAP,
    log_access_denied,
    log_federation_discovery,
    log_federation_rewrap,
)
from audit.exceptions import (
    AuditCommitFailedError,
    AuditError,
    ChainBreakError,
    EmptyChainError,
    TamperedEntryError,
)
from audit.share_custody import Share, release_share_after_commit
from audit.share_registry import ShareNotFoundError, ShareRegistry

__all__ = [
    "GENESIS_PREV_HASH",
    "DENIED_BY_CONSENT",
    "DENIED_BY_CREDENTIAL",
    "DENIED_BY_POLICY",
    "DENIED_BY_REVOCATION_AUTHZ",
    "EVENT_ACCESS_DENIED",
    "EVENT_FEDERATION_DISCOVERY",
    "EVENT_FEDERATION_REWRAP",
    "AuditCommitFailedError",
    "AuditError",
    "ChainBreakError",
    "EmptyChainError",
    "Share",
    "ShareNotFoundError",
    "ShareRegistry",
    "TamperedEntryError",
    "append_entry",
    "compute_entry_hash",
    "create_genesis_entry",
    "log_access_denied",
    "log_federation_discovery",
    "log_federation_rewrap",
    "release_share_after_commit",
    "verify_chain",
    "verify_full_chain",
]
