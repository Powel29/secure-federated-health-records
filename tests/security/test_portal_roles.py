"""The portal's own database role cannot touch the store (review F36).

Claim: the portals store data and identify users but never decide access
(ADR-0014). Their Django connection used to be the postgres superuser, so a
portal bug could rewrite lifecycle state or the audit log. It now connects as
``portal_app``, which owns only the ``portal`` schema.
"""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from storage.migrate import apply_migrations

from tests.security.conftest import skip_or_fail_without_postgres

ROLES_SQL = Path(__file__).resolve().parents[2] / "portal" / "sql" / "roles.sql"
_DB_URL = os.environ.get("DATABASE_URL")
_PASSWORD = "portal_app_test"  # noqa: S105 - throwaway test role password


@pytest.fixture()
def portal_app_conn():
    if not _DB_URL:
        skip_or_fail_without_postgres("DATABASE_URL not set; roles need Postgres")
    try:
        admin = psycopg.connect(_DB_URL, autocommit=True)
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    with admin.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS portal CASCADE")
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;")
    apply_migrations(admin)
    with admin.cursor() as cur:
        cur.execute(ROLES_SQL.read_text(encoding="utf-8"))
        cur.execute(
            sql.SQL("ALTER ROLE portal_app WITH PASSWORD {}").format(
                sql.Literal(_PASSWORD)
            )
        )
    params = conninfo_to_dict(_DB_URL)
    params.update(user="portal_app", password=_PASSWORD)
    conn = psycopg.connect(make_conninfo(**params), autocommit=True)
    yield conn
    conn.close()
    with admin.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS portal CASCADE")
    admin.close()


def test_portal_default_connection_cannot_write_store_tables(portal_app_conn):
    with portal_app_conn.cursor() as cur:
        # Setup is valid: the role can build Django's own tables.
        cur.execute("CREATE TABLE portal.probe (id int)")
        cur.execute("INSERT INTO portal.probe VALUES (1)")

        for statement in (
            "UPDATE public.lifecycle_state SET state = 'granted'",
            "DELETE FROM public.audit_log",
            "DELETE FROM public.consumed_ids",
            "SELECT count(*) FROM public.records",
        ):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                cur.execute(statement)
