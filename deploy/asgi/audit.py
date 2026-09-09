"""ASGI factory for the audit service process (P4-3, C14/C10/C11).

Environment:
    DATABASE_URL: DSN for the shared store.
    AUDIT_ACTOR_ID: Identity this service signs entries as (default
        ``"audit-service"``).
"""

from __future__ import annotations

import os

import psycopg
from api.audit_service import create_audit_app
from fastapi import FastAPI


def app() -> FastAPI:
    """Build the Audit Service app from the environment.

    Opens its own dedicated connection to the shared store -- this process
    is the chain's sole writer, and ``create_audit_app`` switches that
    connection to autocommit so every append is immediately durable
    (ARCHITECTURE.md §7: "if chain verification fails at boot, nothing else
    starts").
    """
    database_url = os.environ["DATABASE_URL"]
    actor_id = os.environ.get("AUDIT_ACTOR_ID", "audit-service")
    conn = psycopg.connect(database_url)
    return create_audit_app(conn, actor_id=actor_id)
