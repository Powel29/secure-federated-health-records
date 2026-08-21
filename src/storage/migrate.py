"""Migration runner for the shared store (C4).

Applies the numbered ``migrations/*.sql`` files in order, exactly once each,
recording what it applied in a ``schema_migrations`` table. Re-running is a
no-op, so "create from a clean database" is reproducible (P0-8 exit criterion).

Run standalone::

    DATABASE_URL=postgresql://... python -m storage.migrate
"""

from __future__ import annotations

import sys
from pathlib import Path

import psycopg

from storage.db import connect

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

_BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename   text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
"""


def migration_files() -> list[Path]:
    """Return the migration files sorted by filename (so 0001 before 0002)."""
    return sorted(MIGRATIONS_DIR.glob("*.sql"))


def apply_migrations(conn: psycopg.Connection) -> list[str]:
    """Apply every un-applied migration in one transaction; return their names."""
    with conn.cursor() as cur:
        cur.execute(_BOOTSTRAP)
        cur.execute("SELECT filename FROM schema_migrations")
        done = {row[0] for row in cur.fetchall()}

    applied: list[str] = []
    for path in migration_files():
        if path.name in done:
            continue
        sql = path.read_text(encoding="utf-8")
        with conn.cursor() as cur:
            cur.execute(sql)
            # Parameterised insert -- never string-built SQL (CONVENTIONS §2 rule 7).
            cur.execute(
                "INSERT INTO schema_migrations (filename) VALUES (%s)", (path.name,)
            )
        applied.append(path.name)
    return applied


def main() -> int:
    """Apply migrations against ``DATABASE_URL`` and report what ran."""
    with connect() as conn:
        applied = apply_migrations(conn)
    if applied:
        print("applied:", ", ".join(applied))
    else:
        print("nothing to apply (schema up to date)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
