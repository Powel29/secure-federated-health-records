"""Thin persistence for the shared store (C4).

Pure storage: every function is a parameterised INSERT or SELECT (CONVENTIONS §2
rule 7 -- never string-built SQL). Nothing here runs crypto or decides access;
crypto material crosses in and out as opaque ``bytes``. Where a frozen contract
exists, the repository speaks that contract; the registry tables that have no
contract use plain arguments and return ``dict`` rows.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import psycopg
from contracts import AuditEntry, DEKWrapping, Facility, Record, TransitionEvent
from contracts.enums import LifecycleState
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

# --- records -----------------------------------------------------------------


def insert_record(conn: psycopg.Connection, rec: Record) -> None:
    """Persist an encrypted record (ciphertext stays opaque)."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO records (record_id, patient_id, facility_id, policy_id,"
            " content_type, ciphertext, nonce, aad, created_at, clinical)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                rec.record_id,
                rec.patient_id,
                rec.facility_id,
                rec.policy_id,
                rec.content_type,
                rec.ciphertext,
                rec.nonce,
                rec.aad,
                rec.created_at,
                Jsonb(rec.clinical.model_dump(mode="json")),
            ),
        )


def get_record(conn: psycopg.Connection, record_id: str) -> Record | None:
    """Fetch a record by id, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM records WHERE record_id = %s", (record_id,))
        row = cur.fetchone()
    return Record(**row) if row else None


# --- dek_wrappings -----------------------------------------------------------


def insert_dek_wrapping(conn: psycopg.Connection, wrap: DEKWrapping) -> None:
    """Persist one wrapped DEK for a record."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO dek_wrappings (wrapping_id, record_id, wrapped_for,"
            " wrapped_dek, nonce, generation, created_at)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                wrap.wrapping_id,
                wrap.record_id,
                wrap.wrapped_for,
                wrap.wrapped_dek,
                wrap.nonce,
                wrap.generation,
                wrap.created_at,
            ),
        )


def get_dek_wrapping(conn: psycopg.Connection, wrapping_id: str) -> DEKWrapping | None:
    """Fetch a wrapped DEK by id, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM dek_wrappings WHERE wrapping_id = %s", (wrapping_id,)
        )
        row = cur.fetchone()
    return DEKWrapping(**row) if row else None


# --- facilities --------------------------------------------------------------


def insert_facility(conn: psycopg.Connection, fac: Facility) -> None:
    """Persist a federation facility node."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO facilities (facility_id, display_name, endpoint,"
            " public_key, status) VALUES (%s, %s, %s, %s, %s)",
            (
                fac.facility_id,
                fac.display_name,
                fac.endpoint,
                fac.public_key,
                fac.status.value,
            ),
        )


def get_facility(conn: psycopg.Connection, facility_id: str) -> Facility | None:
    """Fetch a facility by id, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM facilities WHERE facility_id = %s", (facility_id,))
        row = cur.fetchone()
    return Facility(**row) if row else None


# --- transition_events -------------------------------------------------------


def insert_transition_event(conn: psycopg.Connection, ev: TransitionEvent) -> None:
    """Persist a signed lifecycle transition."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO transition_events (event_id, record_id, from_state,"
            " to_state, actor_id, reason_code, issued_at, nonce, signature)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                ev.event_id,
                ev.record_id,
                ev.from_state.value,
                ev.to_state.value,
                ev.actor_id,
                ev.reason_code.value if ev.reason_code else None,
                ev.issued_at,
                ev.nonce,
                ev.signature,
            ),
        )


def get_transition_event(
    conn: psycopg.Connection, event_id: str
) -> TransitionEvent | None:
    """Fetch a transition event by id, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM transition_events WHERE event_id = %s::uuid", (event_id,)
        )
        row = cur.fetchone()
    return TransitionEvent(**row) if row else None


# --- audit_log ---------------------------------------------------------------


def insert_audit_entry(conn: psycopg.Connection, entry: AuditEntry) -> None:
    """Append one hash-chained audit entry (event_data is metadata only)."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (seq, prev_hash, entry_hash, event_type,"
            " event_data, actor_id, correlation_id, recorded_at, signature)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                entry.seq,
                entry.prev_hash,
                entry.entry_hash,
                entry.event_type,
                Jsonb(entry.event_data),
                entry.actor_id,
                entry.correlation_id,
                entry.timestamp,
                entry.signature,
            ),
        )


def get_audit_entry(conn: psycopg.Connection, seq: int) -> AuditEntry | None:
    """Fetch an audit entry by sequence number, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM audit_log WHERE seq = %s", (seq,))
        row = cur.fetchone()
    if not row:
        return None
    # recorded_at carries the contract's `timestamp` field (renamed in SQL).
    row["timestamp"] = row.pop("recorded_at")
    return AuditEntry(**row)


def get_chain_head(conn: psycopg.Connection) -> AuditEntry | None:
    """Fetch the highest-``seq`` audit entry (the current chain head).

    Cross-owner addition for P3-3/P3-4 (``audit``, C10) -- flagged for
    review the same way P2-3's cross-owner ``authority`` edit was (see
    WORKFLOW.md P2-3). Returns ``None`` only before genesis has been
    appended.
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
    if not row:
        return None
    row["timestamp"] = row.pop("recorded_at")
    return AuditEntry(**row)


def list_audit_entries(conn: psycopg.Connection) -> list[AuditEntry]:
    """Fetch the full audit chain in ``seq`` order, genesis first.

    Cross-owner addition for P3-3 (``audit``, C10) -- same flag as
    :func:`get_chain_head`. Used for full-chain verification
    (ARCHITECTURE.md §7 boot check).
    """
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM audit_log ORDER BY seq ASC")
        rows = cur.fetchall()
    entries = []
    for row in rows:
        row["timestamp"] = row.pop("recorded_at")
        entries.append(AuditEntry(**row))
    return entries


# --- registry tables (no frozen contract) ------------------------------------


def insert_authority(
    conn: psycopg.Connection, authority_id: str, display_name: str, public_key: bytes
) -> None:
    """Register an attribute authority and its public key."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO authorities (authority_id, display_name, public_key)"
            " VALUES (%s, %s, %s)",
            (authority_id, display_name, public_key),
        )


def get_authority(conn: psycopg.Connection, authority_id: str) -> dict[str, Any] | None:
    """Fetch an authority row, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            "SELECT * FROM authorities WHERE authority_id = %s", (authority_id,)
        )
        return cur.fetchone()


def insert_patient(
    conn: psycopg.Connection, patient_id: str, home_authority_id: str
) -> None:
    """Register a patient identifier and its home authority (no PHI)."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO patients (patient_id, home_authority_id) VALUES (%s, %s)",
            (patient_id, home_authority_id),
        )


def get_patient(conn: psycopg.Connection, patient_id: str) -> dict[str, Any] | None:
    """Fetch a patient row, or ``None`` if absent."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM patients WHERE patient_id = %s", (patient_id,))
        return cur.fetchone()


def insert_attribute(
    conn: psycopg.Connection, authority_id: str, name: str, value: str
) -> None:
    """Register that an authority owns a name:value attribute."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO attributes (authority_id, name, value) VALUES (%s, %s, %s)",
            (authority_id, name, value),
        )


def upsert_lifecycle_state(
    conn: psycopg.Connection,
    record_id: str,
    state: LifecycleState,
    last_event_id: str | None = None,
) -> None:
    """Set (or overwrite) a record's lifecycle state.

    Test seeding only. Production code creates the row with
    :func:`insert_lifecycle_state` and changes it with
    :func:`transition_lifecycle_state`, so no write can silently undo another
    (review N1).
    """
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO lifecycle_state (record_id, state, last_event_id,"
            " updated_at) VALUES (%s, %s, %s, now())"
            " ON CONFLICT (record_id) DO UPDATE SET state = EXCLUDED.state,"
            " last_event_id = EXCLUDED.last_event_id, updated_at = now()",
            (record_id, state.value, last_event_id),
        )


def insert_lifecycle_state(
    conn: psycopg.Connection,
    record_id: str,
    state: LifecycleState,
    last_event_id: str | None = None,
) -> bool:
    """Create a record's first lifecycle-state row (ingest only, review N1).

    Never overwrites: returns ``False`` if a row already exists, so the caller
    can refuse. Every later change goes through
    :func:`transition_lifecycle_state`.
    """
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO lifecycle_state (record_id, state, last_event_id,"
            " updated_at) VALUES (%s, %s, %s, now())"
            " ON CONFLICT (record_id) DO NOTHING",
            (record_id, state.value, last_event_id),
        )
        return cur.rowcount == 1


def get_lifecycle_state(
    conn: psycopg.Connection, record_id: str
) -> dict[str, Any] | None:
    """Fetch the current lifecycle-state row for a record, or ``None``."""
    with conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT * FROM lifecycle_state WHERE record_id = %s", (record_id,))
        return cur.fetchone()


def transition_lifecycle_state(
    conn: psycopg.Connection,
    record_id: str,
    expected: LifecycleState,
    new: LifecycleState,
    last_event_id: str | None = None,
) -> bool:
    """Compare-and-set a record's state (review F12).

    Updates only if the stored state is still ``expected``, so two concurrent
    transitions from the same state cannot both succeed. Returns ``True`` if
    this call made the change, ``False`` if the state had moved on (the caller
    must treat that as a conflict, never as success).
    """
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE lifecycle_state SET state = %s, last_event_id = %s,"
            " updated_at = now() WHERE record_id = %s AND state = %s",
            (new.value, last_event_id, record_id, expected.value),
        )
        return cur.rowcount == 1


# --- one-time ids (review F22) ------------------------------------------------


def consume_id(conn: psycopg.Connection, kind: str, item_id: UUID) -> bool:
    """Record a one-time id; ``True`` on first use, ``False`` on a replay."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO consumed_ids (kind, id) VALUES (%s, %s)"
            " ON CONFLICT (kind, id) DO NOTHING",
            (kind, item_id),
        )
        return cur.rowcount == 1


def has_consumed_id(conn: psycopg.Connection, kind: str, item_id: UUID) -> bool:
    """Whether a one-time id has been consumed (diagnostics and tests only)."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM consumed_ids WHERE kind = %s AND id = %s", (kind, item_id)
        )
        return cur.fetchone() is not None


def insert_search_term(
    conn: psycopg.Connection, record_id: str, coded_term: bytes
) -> None:
    """Append one coded (opaque) search term for a record."""
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO search_index (record_id, coded_term) VALUES (%s, %s)",
            (record_id, coded_term),
        )


def replace_search_index(
    conn: psycopg.Connection, record_id: str, coded_terms: list[bytes]
) -> None:
    """Replace all search tokens for one record atomically."""
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM search_index WHERE record_id = %s",
            (record_id,),
        )
        for coded_term in coded_terms:
            cur.execute(
                "INSERT INTO search_index (record_id, coded_term) VALUES (%s, %s)",
                (record_id, coded_term),
            )


def find_records_by_search_term(
    conn: psycopg.Connection, coded_term: bytes
) -> list[str]:
    """Return record IDs whose search_index row matches an opaque coded_term."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT record_id FROM search_index WHERE coded_term = %s",
            (coded_term,),
        )
        rows = cur.fetchall()

    return [row[0] for row in rows]
