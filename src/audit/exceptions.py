"""Exceptions for the audit module (C10, ARCHITECTURE.md §2 C10, §5).

Every failure mode in chain verification and share-custody commit has its own
exception, all extending ``AuditError`` so callers can catch the whole family.
``AuditError`` extends ``CryptoError`` to stay in the project-wide exception
hierarchy (matches ``lifecycle.exceptions.LifecycleError``,
``breakglass.exceptions.BreakglassError``).
"""

from __future__ import annotations

from crypto_core.exceptions import CryptoError


class AuditError(CryptoError):
    """Base exception for all audit-module failures."""


# ---------------------------------------------------------------------------
# Chain verification (P3-3)
# ---------------------------------------------------------------------------


class ChainBreakError(AuditError):
    """An entry's ``prev_hash``/``seq`` does not link to its true predecessor.

    ARCHITECTURE.md §2 C10: the chain is ``h_i = SHA-256(h_{i-1} ‖ event ‖
    timestamp ‖ actor)``. A broken link means either the wrong entry was
    spliced in, an entry was deleted, or ``seq`` is out of order -- any of
    which must fail closed rather than verify "close enough."
    """


class TamperedEntryError(AuditError):
    """An entry's stored ``entry_hash`` does not match the recomputed hash.

    Caught after signature verification: a legitimately-signed entry whose
    hash still fails to recompute indicates the signer itself mis-chained it,
    which is exactly the "tampered entry" property CONVENTIONS.md §5 requires
    a negative test for.
    """


class EmptyChainError(AuditError):
    """An operation that requires an existing chain found none.

    Raised by :func:`audit.chain.append_entry` when no genesis entry exists
    yet, and by :func:`audit.chain.verify_full_chain` when the chain is
    empty. A chain must start from an explicit genesis entry
    (ARCHITECTURE.md §7 bootstrap step 4) -- there is no implicit "first
    entry is its own genesis" fallback.
    """


# ---------------------------------------------------------------------------
# Log-before-release (P3-4)
# ---------------------------------------------------------------------------


class AuditCommitFailedError(AuditError):
    """The audit log entry could not be durably committed.

    ARCHITECTURE.md §5 step 3 / CONVENTIONS.md §5: "break-glass fails closed
    when the audit service cannot commit its log entry." Raised by
    :func:`audit.share_custody.release_share_after_commit` when the
    underlying append fails for any reason -- the share is never
    constructed as a return value when this is raised.
    """
