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


@pytest.fixture(scope="session")
def _base_conn():
    if not _URL:
        pytest.skip("DATABASE_URL not set; this test needs Postgres")
    try:
        conn = psycopg.connect(_URL)
    except psycopg.OperationalError as exc:
        pytest.skip(f"cannot reach Postgres: {exc}")
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
