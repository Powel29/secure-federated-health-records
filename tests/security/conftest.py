"""Shared fixtures for the negative security suite that need real Postgres.

Same shape as ``tests/storage/conftest.py`` / ``tests/audit/conftest.py``:
if ``DATABASE_URL`` is unset or unreachable, tests depending on ``conn`` skip
cleanly rather than failing a clone without Postgres.
"""

from __future__ import annotations

import os

import psycopg
import pytest
from crypto_core import generate_ec_keypair
from storage.migrate import apply_migrations

_URL = os.environ.get("DATABASE_URL")


def skip_or_fail_without_postgres(reason: str) -> None:
    """Skip on a laptop, fail in CI (review F42).

    The audit-commit and chain-tamper claims (P5-1 C2, C5) are Postgres-backed;
    in CI a missing database must not silently drop them from the evidence.
    """
    if os.environ.get("CI", "").lower() == "true":
        pytest.fail(f"{reason} -- Postgres is required in CI", pytrace=False)
    pytest.skip(reason)


@pytest.fixture(scope="session")
def _base_conn():
    if not _URL:
        skip_or_fail_without_postgres("DATABASE_URL not set; this test needs Postgres")
    try:
        conn = psycopg.connect(_URL)
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    conn.autocommit = False
    apply_migrations(conn)
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture
def conn(_base_conn):
    """A connection whose per-test writes are rolled back for isolation."""
    yield _base_conn
    _base_conn.rollback()


@pytest.fixture(scope="session")
def audit_keypair():
    """The audit service's signing keypair, fixed for the whole session."""
    return generate_ec_keypair()
