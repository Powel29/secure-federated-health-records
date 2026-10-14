"""Read-only views onto the P0-8 store tables (ADR-0021).

Every query here runs on the ``store`` database alias, whose role has SELECT only.
These functions never write, never decrypt, and never decide access -- they show
what the store holds (ciphertext + metadata) so the portals can display real
data. If a write were attempted it would fail at the database.

What is *never* selected: ``ciphertext`` bytes, ``wrapped_dek``, nonces,
signatures, ``coded_term``. Sizes and hashes only.
"""

from __future__ import annotations

from typing import Any

from django.db import connections
from psycopg import sql

# Composed with psycopg.sql, never by string formatting (CONVENTIONS §2 rule 7,
# review F35). Values still travel only as bound parameters.
_AUDIT_COLUMNS = sql.SQL(
    "seq, event_type, event_data, actor_id, correlation_id, recorded_at,"
    " encode(entry_hash, 'hex') AS entry_hash_hex,"
    " encode(prev_hash, 'hex') AS prev_hash_hex"
)

# Event types that mean a record was opened under emergency access. Used by the
# patient history view to badge break-glass rows and by the admin case review.
BREAKGLASS_EVENT_TYPES = (
    "breakglass_share_released",
    "breakglass_share_release",
    "federation.rewrap",
)
LIFECYCLE_EVENT_TYPES = ("lifecycle_transition", "transition")


def _rows(
    query: str | sql.Composable, params: tuple[Any, ...] = ()
) -> list[dict[str, Any]]:
    with connections["store"].cursor() as cur:
        cur.execute(query, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]


def _one(
    query: str | sql.Composable, params: tuple[Any, ...] = ()
) -> dict[str, Any] | None:
    rows = _rows(query, params)
    return rows[0] if rows else None


# --- Audit chain ---------------------------------------------------------------


def recent_audit(limit: int = 50) -> list[dict[str, Any]]:
    """Most recent audit-chain entries (metadata only; never key material)."""
    return _rows(
        sql.SQL("SELECT {} FROM audit_log ORDER BY seq DESC LIMIT %s").format(
            _AUDIT_COLUMNS
        ),
        (limit,),
    )


def audit_by_correlation(correlation_id: str) -> list[dict[str, Any]]:
    """Every entry of one flow, genesis-order (ADR-0017 correlation IDs)."""
    return _rows(
        sql.SQL(
            "SELECT {} FROM audit_log WHERE correlation_id = %s ORDER BY seq ASC"
        ).format(_AUDIT_COLUMNS),
        (correlation_id,),
    )


def audit_for_patient(
    patient_id: str, record_ids: list[str], limit: int = 200
) -> list[dict[str, Any]]:
    """Entries that concern one patient: by patient_id, or by any of their records.

    Matches on the JSON ``event_data`` the emitting module wrote (``record_id``,
    ``patient_id``) -- the shapes fixed by ``audit.events`` (ADR-0038) and the
    break-glass release / lifecycle transition payloads.
    """
    return _rows(
        sql.SQL(
            "SELECT {} FROM audit_log"
            " WHERE event_data->>'patient_id' = %s"
            "    OR event_data->>'record_id' = ANY(%s)"
            "    OR correlation_id IN ("
            "        SELECT correlation_id FROM audit_log"
            "        WHERE event_data->>'patient_id' = %s"
            "           OR event_data->>'record_id' = ANY(%s))"
            " ORDER BY seq DESC LIMIT %s"
        ).format(_AUDIT_COLUMNS),
        (patient_id, record_ids, patient_id, record_ids, limit),
    )


def chain_stats() -> dict[str, Any]:
    head = _one(
        "SELECT seq, encode(entry_hash, 'hex') AS entry_hash_hex, recorded_at"
        " FROM audit_log ORDER BY seq DESC LIMIT 1"
    )
    count = _one("SELECT count(*) AS n FROM audit_log")
    return {"head": head, "length": (count or {}).get("n", 0)}


def breakglass_correlations(limit: int = 100) -> list[dict[str, Any]]:
    """Distinct break-glass flows seen in the chain, newest first."""
    return _rows(
        "SELECT correlation_id, min(seq) AS first_seq, max(seq) AS last_seq,"
        " min(recorded_at) AS started_at, count(*) AS entries,"
        " bool_or(event_type = ANY(%s)) AS released,"
        " bool_or(event_type = ANY(%s) AND event_data->>'to_state' = 'expired')"
        "   AS expired"
        " FROM audit_log WHERE correlation_id IN ("
        "   SELECT correlation_id FROM audit_log WHERE event_type = ANY(%s))"
        " GROUP BY correlation_id ORDER BY max(seq) DESC LIMIT %s",
        (
            list(BREAKGLASS_EVENT_TYPES),
            list(LIFECYCLE_EVENT_TYPES),
            list(BREAKGLASS_EVENT_TYPES),
            limit,
        ),
    )


def event_type_counts() -> list[dict[str, Any]]:
    return _rows(
        "SELECT event_type, count(*) AS n FROM audit_log"
        " GROUP BY event_type ORDER BY n DESC"
    )


# --- Records and lifecycle -------------------------------------------------------


def record_summaries(limit: int = 50) -> list[dict[str, Any]]:
    """Records as metadata + ciphertext size -- the plaintext is never here."""
    return _rows(
        "SELECT r.record_id, r.patient_id, r.facility_id, r.content_type,"
        " octet_length(r.ciphertext) AS ciphertext_bytes, r.created_at, r.clinical,"
        " f.display_name AS facility_name, l.state AS lifecycle_state"
        " FROM records r"
        " LEFT JOIN facilities f ON f.facility_id = r.facility_id"
        " LEFT JOIN lifecycle_state l ON l.record_id = r.record_id"
        " ORDER BY r.created_at DESC LIMIT %s",
        (limit,),
    )


def records_for_patient(patient_id: str) -> list[dict[str, Any]]:
    """The patient's own records (metadata); the ADR-0016 self-access surface."""
    return _rows(
        "SELECT r.record_id, r.patient_id, r.facility_id, r.content_type,"
        " octet_length(r.ciphertext) AS ciphertext_bytes, r.created_at, r.clinical,"
        " f.display_name AS facility_name, l.state AS lifecycle_state,"
        " (SELECT max(generation) FROM dek_wrappings w WHERE w.record_id = r.record_id)"
        "   AS generation"
        " FROM records r"
        " LEFT JOIN facilities f ON f.facility_id = r.facility_id"
        " LEFT JOIN lifecycle_state l ON l.record_id = r.record_id"
        " WHERE r.patient_id = %s ORDER BY r.created_at DESC",
        (patient_id,),
    )


def record_meta(record_id: str) -> dict[str, Any] | None:
    return _one(
        "SELECT r.record_id, r.patient_id, r.facility_id, r.content_type,"
        " octet_length(r.ciphertext) AS ciphertext_bytes, r.created_at, r.clinical,"
        " f.display_name AS facility_name, l.state AS lifecycle_state"
        " FROM records r"
        " LEFT JOIN facilities f ON f.facility_id = r.facility_id"
        " LEFT JOIN lifecycle_state l ON l.record_id = r.record_id"
        " WHERE r.record_id = %s",
        (record_id,),
    )


def lifecycle_states() -> list[dict[str, Any]]:
    """Current lifecycle state per record."""
    return _rows(
        "SELECT record_id, state, updated_at FROM lifecycle_state"
        " ORDER BY updated_at DESC"
    )


def transition_events_for_record(record_id: str) -> list[dict[str, Any]]:
    return _rows(
        "SELECT event_id, record_id, from_state, to_state, actor_id, reason_code,"
        " issued_at FROM transition_events WHERE record_id = %s"
        " ORDER BY issued_at DESC",
        (record_id,),
    )


# --- Federation topology --------------------------------------------------------


def facilities() -> list[dict[str, Any]]:
    return _rows(
        "SELECT facility_id, display_name, endpoint, status FROM facilities"
        " ORDER BY facility_id"
    )


def authorities() -> list[dict[str, Any]]:
    return _rows(
        "SELECT authority_id, display_name, created_at FROM authorities"
        " ORDER BY authority_id"
    )


def patient_row(patient_id: str) -> dict[str, Any] | None:
    return _one(
        "SELECT patient_id, home_authority_id, created_at FROM patients"
        " WHERE patient_id = %s",
        (patient_id,),
    )


def table_counts() -> dict[str, int]:
    out: dict[str, int] = {}
    for table in (
        "records",
        "dek_wrappings",
        "search_index",
        "audit_log",
        "transition_events",
        "patients",
    ):
        row = _one(
            sql.SQL("SELECT count(*) AS n FROM {}").format(sql.Identifier(table))
        )
        out[table] = int((row or {}).get("n", 0))
    return out
