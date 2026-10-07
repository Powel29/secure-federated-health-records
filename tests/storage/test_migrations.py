"""The migration creates every table ARCHITECTURE §2 C4 names, and is idempotent."""

from __future__ import annotations

from storage.migrate import apply_migrations

_EXPECTED = {
    "patients",
    "records",
    "dek_wrappings",
    "attributes",
    "authorities",
    "facilities",
    "lifecycle_state",
    "transition_events",
    "audit_log",
    "search_index",
    "consumed_ids",  # 0002, review F22
}


def test_all_ten_tables_exist(conn):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT table_name FROM information_schema.tables"
            " WHERE table_schema = 'public'"
        )
        names = {row[0] for row in cur.fetchall()}
    assert _EXPECTED <= names


def test_reapplying_migrations_is_a_noop(conn):
    # The session fixture already applied 0001; applying again does nothing.
    assert apply_migrations(conn) == []
