"""Unit-test settings: SQLite `default`, no `store` alias.

For portal view/model tests that exercise identity, registration, and rendering
without the store. The real store-read path (the `store` alias + read-only role)
is Postgres-only and is verified against Postgres, not here.
"""

from __future__ import annotations

from config.settings import *  # noqa: F401,F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
DATABASE_ROUTERS: list[str] = []
