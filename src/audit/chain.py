"""Hash-chained, signed audit log (C10, ARCHITECTURE.md §2 C10, §5, §7).

The chain: ``h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)``. This module
computes and verifies that formula, and produces the ECDSA signature every
:class:`~contracts.AuditEntry` carries. ``event_data`` is metadata only --
identifiers and hashes, never key material, shares, DEKs, or plaintext record
contents (CONVENTIONS.md §2 rule 3); every event-emitting caller is
responsible for honouring that, this module only encodes and hashes whatever
it is given.

Hashed and signed bytes use ``crypto_core.encode_fields``: a domain tag, then
length-prefixed fields
(ADR-0077), so no ``event_type`` or ``actor_id`` can shift a field boundary. See
``docs/adr/0034-audit-hash-chain-and-share-release.md`` for why ``event_data``
is JSON-canonicalised and why the signature covers the *whole* entry rather
than just ``entry_hash``.
"""

from __future__ import annotations

import datetime
import json
from collections.abc import Sequence
from typing import Any

import psycopg
from contracts import AuditEntry
from contracts.base import SHA256_DIGEST_BYTES
from crypto_core import encode_fields, sha256_digest, sign, verify
from crypto_core.types import ECPrivateKey, ECPublicKey
from storage import repositories as repo

from audit.exceptions import ChainBreakError, EmptyChainError, TamperedEntryError

# encode_fields domain tags (ADR-0077).
_EVENT_DOMAIN = "ehr/audit-event/v1"
_LINK_DOMAIN = "ehr/audit-chain-link/v1"
_ENTRY_DOMAIN = "ehr/audit-entry/v1"

# The genesis link value -- 32 zero bytes, matching SHA256_DIGEST_BYTES.
# ARCHITECTURE.md §7 bootstrap step 4: "initialises the hash chain with a
# genesis entry h_0."
GENESIS_PREV_HASH = b"\x00" * SHA256_DIGEST_BYTES

_GENESIS_EVENT_TYPE = "genesis"
_GENESIS_CORRELATION_ID = "genesis"


def _canonical_event(event_type: str, event_data: dict[str, Any]) -> bytes:
    """Canonical bytes for the ``event`` term in the chain-hash formula.

    ``event_data`` is JSON-canonicalised (sorted keys, no whitespace) so the
    same logical event always hashes to the same bytes regardless of dict
    insertion order.
    """
    encoded_data = json.dumps(event_data, sort_keys=True, separators=(",", ":"))
    return encode_fields(
        _EVENT_DOMAIN, [event_type.encode("utf-8"), encoded_data.encode("utf-8")]
    )


def _chain_link_payload(
    *,
    prev_hash: bytes,
    event_type: str,
    event_data: dict[str, Any],
    timestamp: datetime.datetime,
    actor_id: str,
) -> bytes:
    """Bytes for exactly ``h_{i-1} ‖ event ‖ timestamp ‖ actor`` (§2 C10)."""
    fields = [
        prev_hash,
        _canonical_event(event_type, event_data),
        timestamp.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
        actor_id.encode("utf-8"),
    ]
    return encode_fields(_LINK_DOMAIN, fields)


def compute_entry_hash(
    *,
    prev_hash: bytes,
    event_type: str,
    event_data: dict[str, Any],
    timestamp: datetime.datetime,
    actor_id: str,
) -> bytes:
    """Compute ``h_i`` per the ARCHITECTURE.md §2 C10 chain formula."""
    payload = _chain_link_payload(
        prev_hash=prev_hash,
        event_type=event_type,
        event_data=event_data,
        timestamp=timestamp,
        actor_id=actor_id,
    )
    return sha256_digest(payload)


def _entry_signing_payload(
    *,
    seq: int,
    prev_hash: bytes,
    entry_hash: bytes,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    timestamp: datetime.datetime,
) -> bytes:
    """Bytes the entry's ECDSA signature covers.

    Broader than :func:`_chain_link_payload`: it also binds ``seq``,
    ``entry_hash``, and ``correlation_id`` -- fields the chain-hash formula
    itself does not cover -- so tampering with any one of them is caught by
    signature verification rather than slipping past hash-chain verification
    alone.
    """
    fields = [
        str(seq).encode("utf-8"),
        prev_hash,
        entry_hash,
        _canonical_event(event_type, event_data),
        actor_id.encode("utf-8"),
        correlation_id.encode("utf-8"),
        timestamp.astimezone(datetime.timezone.utc).isoformat().encode("utf-8"),
    ]
    return encode_fields(_ENTRY_DOMAIN, fields)


def _sign_entry_fields(
    *,
    seq: int,
    prev_hash: bytes,
    entry_hash: bytes,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    timestamp: datetime.datetime,
    signing_key: ECPrivateKey,
) -> bytes:
    payload = _entry_signing_payload(
        seq=seq,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        event_type=event_type,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        timestamp=timestamp,
    )
    return sign(signing_key, payload)


# ---------------------------------------------------------------------------
# Building entries
# ---------------------------------------------------------------------------


def create_genesis_entry(
    *,
    signing_key: ECPrivateKey,
    actor_id: str = "audit-service",
    timestamp: datetime.datetime | None = None,
) -> AuditEntry:
    """Build and sign the chain's genesis entry (``seq=0``).

    Args:
        signing_key: The audit service's ECDSA-P256 private key.
        actor_id: Identifier for the party initialising the chain.
        timestamp: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        A signed :class:`~contracts.AuditEntry` with ``seq=0`` and
        ``prev_hash=GENESIS_PREV_HASH``.

    Security property:
        Every subsequent entry's chain ultimately roots in this one signed
        artifact; nothing in the chain is trustworthy without it.
    """
    when = timestamp or datetime.datetime.now(datetime.timezone.utc)
    entry_hash = compute_entry_hash(
        prev_hash=GENESIS_PREV_HASH,
        event_type=_GENESIS_EVENT_TYPE,
        event_data={},
        timestamp=when,
        actor_id=actor_id,
    )
    signature = _sign_entry_fields(
        seq=0,
        prev_hash=GENESIS_PREV_HASH,
        entry_hash=entry_hash,
        event_type=_GENESIS_EVENT_TYPE,
        event_data={},
        actor_id=actor_id,
        correlation_id=_GENESIS_CORRELATION_ID,
        timestamp=when,
        signing_key=signing_key,
    )
    return AuditEntry(
        seq=0,
        prev_hash=GENESIS_PREV_HASH,
        entry_hash=entry_hash,
        event_type=_GENESIS_EVENT_TYPE,
        event_data={},
        actor_id=actor_id,
        correlation_id=_GENESIS_CORRELATION_ID,
        timestamp=when,
        signature=signature,
    )


def append_entry(
    conn: psycopg.Connection,
    *,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    signing_key: ECPrivateKey,
    timestamp: datetime.datetime | None = None,
) -> AuditEntry:
    """Append one new entry onto the chain's current head.

    Args:
        conn: An open ``psycopg.Connection``. Not committed here -- the
            caller controls durability (matches every other module in this
            codebase; see ``storage.db.connect``).
        event_type: e.g. ``"transition"``, ``"breakglass_share_release"``.
        event_data: Metadata only -- identifiers and hashes, never key
            material, shares, DEKs, or plaintext (CONVENTIONS.md §2 rule 3).
        actor_id: The party responsible for the logged event.
        correlation_id: Groups every entry of one logical flow (ADR-0014).
        signing_key: The audit service's ECDSA-P256 private key.
        timestamp: Optional timestamp; defaults to ``utcnow()``.

    Returns:
        The newly persisted, signed :class:`~contracts.AuditEntry`.

    Raises:
        EmptyChainError: No genesis entry exists yet -- the chain must be
            initialised with :func:`create_genesis_entry` first.

    Security property:
        ``seq`` and ``prev_hash`` are derived from the current durable chain
        head, never supplied by the caller, so an append can only ever
        extend the true chain.
    """
    head = repo.get_chain_head(conn)
    if head is None:
        raise EmptyChainError(
            "cannot append: no genesis entry exists; call create_genesis_entry "
            "and persist it first"
        )
    entry = build_entry(
        head=head,
        event_type=event_type,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        signing_key=signing_key,
        timestamp=timestamp,
    )
    repo.insert_audit_entry(conn, entry)
    return entry


def _reject_floats(value: object, path: str = "event_data") -> None:
    """Refuse floats anywhere in ``event_data`` (review F31).

    A float does not survive the jsonb round trip byte for byte (``1e20``
    comes back as ``100000000000000000000``), so the recomputed hash would
    not match and verification would report tampering that never happened.
    Identifiers, counts and timestamps (as strings) are all this log needs.
    """
    if isinstance(value, float):
        raise ValueError(f"{path} holds a float; log integers or strings instead")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")


def build_entry(
    *,
    head: AuditEntry,
    event_type: str,
    event_data: dict[str, Any],
    actor_id: str,
    correlation_id: str,
    signing_key: ECPrivateKey,
    timestamp: datetime.datetime | None = None,
) -> AuditEntry:
    """Build and sign the entry that extends ``head`` (no persistence).

    Raises:
        ValueError: ``event_data`` holds a float (review F31).
    """
    _reject_floats(event_data)
    when = timestamp or datetime.datetime.now(datetime.timezone.utc)
    seq = head.seq + 1
    prev_hash = head.entry_hash

    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        event_type=event_type,
        event_data=event_data,
        timestamp=when,
        actor_id=actor_id,
    )
    signature = _sign_entry_fields(
        seq=seq,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        event_type=event_type,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        timestamp=when,
        signing_key=signing_key,
    )

    return AuditEntry(
        seq=seq,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        event_type=event_type,
        event_data=event_data,
        actor_id=actor_id,
        correlation_id=correlation_id,
        timestamp=when,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_entry_signature(entry: AuditEntry, public_key: ECPublicKey) -> None:
    """Verify one entry's signature and its own hash, without the chain.

    For a client handed a single entry back by the audit service (the
    custodian after a share release, review F31): it proves the audit
    service signed exactly this entry.

    Raises:
        InvalidSignatureError: The signature does not verify.
        TamperedEntryError: The entry's hash does not match its fields.
    """
    verify(
        public_key,
        _entry_signing_payload(
            seq=entry.seq,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
            event_type=entry.event_type,
            event_data=entry.event_data,
            actor_id=entry.actor_id,
            correlation_id=entry.correlation_id,
            timestamp=entry.timestamp,
        ),
        entry.signature,
    )
    recomputed = compute_entry_hash(
        prev_hash=entry.prev_hash,
        event_type=entry.event_type,
        event_data=entry.event_data,
        timestamp=entry.timestamp,
        actor_id=entry.actor_id,
    )
    if recomputed != entry.entry_hash:
        raise TamperedEntryError(f"entry seq={entry.seq} hash does not match")


def verify_chain(
    entries: Sequence[AuditEntry],
    public_key: ECPublicKey,
) -> None:
    """Verify a full chain of entries, genesis through head.

    Checks, per entry, in this order (fail-closed at the first failure):
        1. **Signature** -- covers the whole entry, so tampering with any
           field (including ``correlation_id``, outside the hash formula) is
           caught here first, and reported as forgery rather than as a
           chain break.
        2. **Link** -- ``entry.prev_hash`` equals the previous entry's
           ``entry_hash`` (or :data:`GENESIS_PREV_HASH` for ``seq == 0``).
        3. **Recomputed hash** -- :func:`compute_entry_hash` over the
           entry's own fields equals its stored ``entry_hash``.
        4. **Sequence** -- ``seq`` is exactly ``previous.seq + 1``.

    Args:
        entries: The chain, in ``seq`` order starting from genesis.
        public_key: The audit service's ECDSA-P256 public key.

    Raises:
        EmptyChainError: ``entries`` is empty.
        InvalidSignatureError: An entry's signature does not verify.
        ChainBreakError: A ``prev_hash``/``seq`` link is broken.
        TamperedEntryError: A recomputed ``entry_hash`` does not match the
            stored one.

    Security property:
        Signature verification runs before hash-chain checks (same ordering
        rationale as ``lifecycle.verify_transition_event`` / ADR-0030 §2): a
        tampered entry is reported as forged, not merely as "out of order."
    """
    if not entries:
        raise EmptyChainError("cannot verify an empty chain")

    previous: AuditEntry | None = None
    for entry in entries:
        signing_payload = _entry_signing_payload(
            seq=entry.seq,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
            event_type=entry.event_type,
            event_data=entry.event_data,
            actor_id=entry.actor_id,
            correlation_id=entry.correlation_id,
            timestamp=entry.timestamp,
        )
        verify(public_key, signing_payload, entry.signature)

        expected_prev_hash = previous.entry_hash if previous else GENESIS_PREV_HASH
        expected_seq = previous.seq + 1 if previous else 0
        if entry.prev_hash != expected_prev_hash or entry.seq != expected_seq:
            raise ChainBreakError(
                f"entry seq={entry.seq} does not link to its predecessor "
                f"(expected seq={expected_seq}, prev_hash matching predecessor's "
                "entry_hash)"
            )

        recomputed = compute_entry_hash(
            prev_hash=entry.prev_hash,
            event_type=entry.event_type,
            event_data=entry.event_data,
            timestamp=entry.timestamp,
            actor_id=entry.actor_id,
        )
        if recomputed != entry.entry_hash:
            raise TamperedEntryError(
                f"entry seq={entry.seq} recomputed hash does not match stored "
                "entry_hash"
            )

        previous = entry


def verify_full_chain(
    conn: psycopg.Connection,
    public_key: ECPublicKey,
) -> AuditEntry:
    """Fetch and verify the entire persisted chain; return its head.

    Args:
        conn: An open ``psycopg.Connection``.
        public_key: The audit service's ECDSA-P256 public key.

    Returns:
        The chain's head entry (highest ``seq``) once the whole chain has
        verified.

    Raises:
        EmptyChainError / InvalidSignatureError / ChainBreakError /
        TamperedEntryError: See :func:`verify_chain`.

    Security property:
        This is the check ARCHITECTURE.md §7 makes a hard boot precondition:
        "if chain verification fails at boot, nothing else starts."
    """
    entries = repo.list_audit_entries(conn)
    verify_chain(entries, public_key)
    return entries[-1]
