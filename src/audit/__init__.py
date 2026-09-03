"""Hash-chained signed audit log + break-glass share custody (C10).

``chain`` implements the ARCHITECTURE.md §2 C10 formula
(``h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)``) and full-chain
verification (P3-3). ``share_custody`` implements "log-before-release": the
audit service's held break-glass share is returned only after its log entry
durably commits (P3-4, ARCHITECTURE.md §5 step 3).
"""

from audit.chain import (
    GENESIS_PREV_HASH,
    append_entry,
    compute_entry_hash,
    create_genesis_entry,
    verify_chain,
    verify_full_chain,
)
from audit.exceptions import (
    AuditCommitFailedError,
    AuditError,
    ChainBreakError,
    EmptyChainError,
    TamperedEntryError,
)
from audit.share_custody import Share, release_share_after_commit

__all__ = [
    "GENESIS_PREV_HASH",
    "AuditCommitFailedError",
    "AuditError",
    "ChainBreakError",
    "EmptyChainError",
    "Share",
    "TamperedEntryError",
    "append_entry",
    "compute_entry_hash",
    "create_genesis_entry",
    "release_share_after_commit",
    "verify_chain",
    "verify_full_chain",
]
