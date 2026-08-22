"""Read-only views onto the P0-8 store tables (ADR-0021).

Every query here runs on the ``store`` database alias, whose role has SELECT only.
These functions never write, never decrypt, and never decide access -- they show
what the store holds (ciphertext + metadata) so the admin/audit portal can
display real data. If a write were attempted it would fail at the database.
"""

from __future__ import annotations

from typing import Any

from django.db import connections


def _rows(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with connections["store"].cursor() as cur:
        cur.execute(sql, params)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]


def recent_audit(limit: int = 50) -> list[dict[str, Any]]:
    """Most recent audit-chain entries (metadata only; never key material)."""
    return _rows(
        "SELECT seq, event_type, actor_id, correlation_id, recorded_at"
        " FROM audit_log ORDER BY seq DESC LIMIT %s",
        (limit,),
    )


def record_summaries(limit: int = 50) -> list[dict[str, Any]]:
    """Records as metadata + ciphertext size -- the plaintext is never here."""
    return _rows(
        "SELECT record_id, patient_id, facility_id, content_type,"
        " octet_length(ciphertext) AS ciphertext_bytes, created_at"
        " FROM records ORDER BY created_at DESC LIMIT %s",
        (limit,),
    )


def lifecycle_states() -> list[dict[str, Any]]:
    """Current lifecycle state per record."""
    return _rows(
        "SELECT record_id, state, updated_at FROM lifecycle_state"
        " ORDER BY updated_at DESC"
    )
