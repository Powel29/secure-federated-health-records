"""Search-token derivation and index management (C12).

The construction is documented in ``docs/adr/0027-search-token-construction.md``:
a coded_term is HKDF-SHA256 over the emergency key with a versioned salt and a
domain-separated info string carrying the search term. Two records that index
the same plaintext term produce identical coded_terms -- this deterministic-SSE
leakage is documented in the ADR and the paper's limitations section.

Tokens derive from the emergency key by design (ARCHITECTURE §2 C12), so search
capability exists only while the record is in Emergency-open and is dead once
the emergency key is destroyed (P3-8 wires the lifecycle side of this).
"""

from __future__ import annotations

import psycopg
from crypto_core.symmetric import hkdf_derive
from storage.repositories import (
    find_records_by_search_term,
    insert_search_term,
)

# Versioned per ADR-0027 so a future construction change is a bytes-level
# migration, not a silent break of already-indexed rows. Mirrors the pattern
# in ``pre/elgamal.py`` (_KDF_SALT / _KDF_INFO).
_KDF_SALT = b"search-token-v1"
_KDF_INFO_PREFIX = b"health-record-search:"
_TOKEN_BYTES = 32


def derive_search_token(emergency_key: bytes, search_term: str) -> bytes:
    """Derive the coded search token for one plaintext ``search_term``.

    Deterministic in ``(emergency_key, search_term)``: the same inputs always
    produce the same token, which is what makes equality search work. See the
    ADR for the leakage this implies.
    """
    info = _KDF_INFO_PREFIX + search_term.encode("utf-8")
    return hkdf_derive(
        ikm=emergency_key,
        salt=_KDF_SALT,
        info=info,
        length=_TOKEN_BYTES,
    )


def index_search_term(
    conn: psycopg.Connection,
    record_id: str,
    emergency_key: bytes,
    search_term: str,
) -> bytes:
    """Compute and persist the coded token for one (record, term) pair."""
    coded_term = derive_search_token(emergency_key, search_term)
    insert_search_term(conn, record_id, coded_term)
    return coded_term


def search_records(conn: psycopg.Connection, coded_term: bytes) -> list[str]:
    """Return record IDs whose search_index row matches the coded token."""
    return find_records_by_search_term(conn, coded_term)


def search_records_with_emergency(
    conn: psycopg.Connection,
    expiry_manager,
    record_id: str,
    search_term: str,
) -> list[str]:
    """Search using the currently active emergency session."""
    emergency_key = expiry_manager.get_active_emergency_key(record_id)
    coded_term = derive_search_token(emergency_key, search_term)
    return find_records_by_search_term(conn, coded_term)
