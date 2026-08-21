"""The shared encrypted store (C4): schema, migrations, and repositories.

Persists ciphertext, wrapped keys, and identifiers. Holds no key material in the
clear and never decides access (ADR-0014 / ADR-0011).
"""

from __future__ import annotations

from storage.db import connect, dsn

__all__ = ["connect", "dsn"]
