"""Database connection helper for the shared store (C4).

The DSN comes from the ``DATABASE_URL`` environment variable (ARCHITECTURE §7:
"Ports ... are configuration, not constants in code"). Nothing here runs crypto
or makes an access decision -- this module only opens connections.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg


def dsn() -> str:
    """Return the configured database DSN.

    Raises:
        RuntimeError: ``DATABASE_URL`` is not set -- fail closed rather than
            silently connecting somewhere unintended.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set")
    return url


@contextmanager
def connect(url: str | None = None) -> Iterator[psycopg.Connection]:
    """Open a connection, commit on success, roll back on error, always close."""
    conn = psycopg.connect(url or dsn())
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
