"""Fixtures for audit tests.

Same shape as ``tests/storage/conftest.py``: these need a real Postgres (the
``audit_log`` table is Postgres-specific). If ``DATABASE_URL`` is unset or
unreachable, the whole audit suite SKIPS cleanly.
"""

from __future__ import annotations

import os

import psycopg
import pytest
from crypto_core import generate_ec_keypair
from storage.migrate import apply_migrations

from tests.security.conftest import skip_or_fail_without_postgres

_URL = os.environ.get("DATABASE_URL")


@pytest.fixture(scope="session")
def _base_conn():
    if not _URL:
        skip_or_fail_without_postgres("DATABASE_URL not set; audit tests need Postgres")
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
