# Initialize module
"""Hospital and Federation API layer (C14).

Exposes the FastAPI applications for facility nodes, authority nodes,
and the audit service. Adheres to CONVENTIONS.md §2 rule 10: orchestration
only, no cryptography inside route handlers.
"""

from __future__ import annotations

from api.hospital import create_hospital_app
from api.repository import (
    InMemoryStorageRepository,
    PostgresStorageRepository,
    StorageRepository,
)

__all__ = [
    "create_hospital_app",
    "StorageRepository",
    "InMemoryStorageRepository",
    "PostgresStorageRepository",
]
