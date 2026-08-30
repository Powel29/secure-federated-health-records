"""Search token derivation for emergency-only encrypted search."""

from crypto_core.symmetric import hkdf_derive
from storage.repositories import (
    find_records_by_search_term,
    insert_search_term,
)


def derive_search_token(
    emergency_key: bytes,
    search_term: str,
) -> bytes:
    """Derive a deterministic search token from the emergency key."""
    return hkdf_derive(
        ikm=emergency_key,
        salt=None,
        info=b"health-record-search:" + search_term.encode("utf-8"),
        length=32,
    )


def index_search_term(
    conn,
    record_id: str,
    emergency_key: bytes,
    search_term: str,
    insert_fn=None,
) -> bytes:
    """Create and store a coded search term for a record."""

    if insert_fn is None:
        insert_fn = insert_search_term

    coded_term = derive_search_token(
        emergency_key,
        search_term,
    )

    insert_fn(
        conn,
        record_id,
        coded_term,
    )

    return coded_term


def search_records(
    conn,
    coded_term: bytes,
) -> list[str]:
    """Find record IDs matching a coded search term."""
    return find_records_by_search_term(
        conn,
        coded_term,
    )