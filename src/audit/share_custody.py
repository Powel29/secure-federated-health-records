"""Log-before-release: the audit service's break-glass share custody (P3-4).

ARCHITECTURE.md §5 step 3 (share 3, the audit service): "The audit service
computes and commits ``h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)``
first, and only then returns its share along with the new chain head. If the
log write fails, no share is returned and break-glass fails closed."

This module is the whole of that precondition. It does not generate, split,
or reconstruct the emergency key -- that is ``breakglass``'s (P3-5) job. It
only custodies an opaque share handed to it and gates its release on a
successful, durable commit of the log entry that records the release.

The share itself must never appear in ``event_data`` -- CONVENTIONS.md §2
rule 3 forbids logging key material, and doing so here would defeat the
entire point of a threshold gate (one party -- the audit service, or anyone
who later reads its log -- would then unilaterally hold the release record's
worth of secret alongside the share).
"""

from __future__ import annotations

import datetime
from typing import Any

import psycopg
from contracts import AuditEntry
from cryptography.hazmat.primitives.asymmetric import ec

from audit.chain import append_entry
from audit.exceptions import AuditCommitFailedError

# The audit service's own share is one (x, share_bytes) pair from
# shamir.split.split_secret -- an opaque payload as far as this module is
# concerned. Type alias only for readability; no shamir math happens here.
Share = tuple[int, bytes]


def release_share_after_commit(
    conn: psycopg.Connection,
    *,
    share: Share,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    signing_key: ec.EllipticCurvePrivateKey,
    timestamp: datetime.datetime | None = None,
) -> tuple[Share, AuditEntry]:
    """Commit a log entry, then release the held share -- never the reverse.

    Args:
        conn: An open ``psycopg.Connection``. The append is wrapped in
            ``conn.transaction()`` (a psycopg3 savepoint when already inside
            an outer transaction), so a failed insert is atomically undone
            and never reaches the caller's connection as a partial write.
        share: The audit service's held ``(x, share_bytes)`` threshold
            share. Never inspected, never placed in ``event_data`` -- only
            ever handed back to the caller on success.
        event_type: Normally ``"breakglass_share_release"``.
        event_data: Metadata only -- e.g. ``assertion_id``, ``patient_id``,
            ``record_id``. **Must never include the share or any other key
            material** (CONVENTIONS.md §2 rule 3); this function does not
            enforce that beyond documenting it, since it has no way to tell
            a hash from a secret.
        actor_id: The audit service's own identifier.
        correlation_id: Ties this entry to the rest of the break-glass flow.
        signing_key: The audit service's ECDSA-P256 private key.
        timestamp: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        ``(share, entry)`` -- the same share handed in, and the freshly
        committed audit entry (the new chain head) -- but only once the
        commit has succeeded.

    Raises:
        AuditCommitFailedError: The log entry could not be committed, for
            any reason (constraint violation, connection failure, or any
            other exception from :func:`audit.chain.append_entry`). The
            share is never constructed as a return value in this case --
            the function raises before ever reaching its ``return``.

    Security property:
        This is the project's headline fail-closed precondition: "no log,
        no share." The ``with conn.transaction()`` block guarantees the
        insert is all-or-nothing, and the exception path is structured so
        there is no code path that returns ``share`` without the block
        having completed successfully first.
    """
    try:
        with conn.transaction():
            entry = append_entry(
                conn,
                event_type=event_type,
                event_data=event_data,
                actor_id=actor_id,
                correlation_id=correlation_id,
                signing_key=signing_key,
                timestamp=timestamp,
            )
    except Exception as exc:
        raise AuditCommitFailedError(
            f"audit log commit failed for correlation_id={correlation_id!r}; "
            "share was not released"
        ) from exc

    return share, entry
