"""DB router: keep the ORM on `default`; never migrate or write the store.

The `store` alias is a read-only window onto the P0-8 tables, queried with raw
SQL (see ``portal_core.store_reader``). No Django model is ever read from,
written to, or migrated on it -- that is the ADR-0021 boundary in code.
"""

from __future__ import annotations

from typing import Any


class PortalRouter:
    def db_for_read(self, model: Any, **hints: Any) -> str:
        return "default"

    def db_for_write(self, model: Any, **hints: Any) -> str:
        return "default"

    def allow_relation(self, obj1: Any, obj2: Any, **hints: Any) -> bool:
        return True

    def allow_migrate(
        self, db: str, app_label: str, **hints: Any
    ) -> bool | None:
        # Only ever migrate `default`; the store schema is owned by P0-8.
        return db == "default"
