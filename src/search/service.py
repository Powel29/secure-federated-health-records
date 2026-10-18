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

import json
from dataclasses import dataclass, field

import psycopg
from crypto_core.exceptions import InvalidTagError
from crypto_core.symmetric import aes_gcm_decrypt, aes_gcm_encrypt, hkdf_derive
from lifecycle.expiry import EmergencyExpiryManager
from storage.repositories import (
    find_records_by_search_term,
    insert_search_term,
    replace_search_index,
)

# Versioned per ADR-0027 so a future construction change is a bytes-level
# migration, not a silent break of already-indexed rows. Mirrors the pattern
# in ``pre/elgamal.py`` (_KDF_SALT / _KDF_INFO).
_KDF_SALT = b"search-token-v1"
_KDF_INFO_PREFIX = b"health-record-search:"
_TOKEN_BYTES = 32

# AAD domain for a record's sealed term list (ADR-0069): the same DEK also
# encrypts the record payload, so the label keeps one ciphertext from being
# accepted as the other, and the record id binds it to its record.
_TERMS_AAD_PREFIX = b"health-record-search-terms-v1:"


class SearchTermsError(ValueError):
    """A sealed term list does not open under this DEK for this record."""


@dataclass(frozen=True)
class SealedSearchTerms:
    """A record's plaintext search terms, AES-256-GCM-sealed under its DEK."""

    ciphertext: bytes = field(repr=False)
    nonce: bytes


def seal_search_terms(
    terms: list[str], dek: bytes, record_id: str
) -> SealedSearchTerms:
    """Seal ``terms`` under the record's DEK so expiry can re-index (ADR-0069).

    The same AES-256-GCM envelope the record payload uses, with a fresh nonce
    and an AAD naming the purpose and the record. Only a holder of the DEK --
    the facility during rotation, or anyone who may read the record -- can
    open it.
    """
    payload = json.dumps(list(terms), ensure_ascii=False, separators=(",", ":"))
    ciphertext, nonce = aes_gcm_encrypt(
        key=dek,
        plaintext=payload.encode("utf-8"),
        aad=_TERMS_AAD_PREFIX + record_id.encode("utf-8"),
    )
    return SealedSearchTerms(ciphertext=ciphertext, nonce=nonce)


def open_search_terms(
    sealed: SealedSearchTerms, dek: bytes, record_id: str
) -> list[str]:
    """Recover the term list :func:`seal_search_terms` sealed.

    Raises:
        SearchTermsError: Wrong DEK, wrong record, or tampered ciphertext.
    """
    try:
        payload = aes_gcm_decrypt(
            key=dek,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
            aad=_TERMS_AAD_PREFIX + record_id.encode("utf-8"),
        )
    except InvalidTagError as exc:
        raise SearchTermsError(
            f"sealed search terms of {record_id!r} do not open"
        ) from exc
    terms = json.loads(payload)
    if not isinstance(terms, list) or not all(isinstance(t, str) for t in terms):
        raise SearchTermsError(f"sealed search terms of {record_id!r} are malformed")
    return terms


def derive_search_token(emergency_key: bytes, search_term: str) -> bytes:
    """Derive the coded search token for one plaintext ``search_term``.

    Deterministic in ``(emergency_key, search_term)``: the same inputs always
    produce the same token, which is what makes equality search work. See the
    ADR for the leakage this implies. The term is trimmed and case-folded
    first, on indexing and on query alike, so "Penicillin" finds "penicillin".
    """
    info = _KDF_INFO_PREFIX + search_term.strip().casefold().encode("utf-8")
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


def rekey_search_index(
    conn: psycopg.Connection,
    record_id: str,
    new_search_key: bytes,
    search_terms: list[str],
) -> list[bytes]:
    """Rebuild one record's search index under a new search key."""
    coded_terms = [derive_search_token(new_search_key, term) for term in search_terms]
    replace_search_index(conn, record_id, coded_terms)
    return coded_terms


def search_records(conn: psycopg.Connection, coded_term: bytes) -> list[str]:
    """Return record IDs whose search_index row matches the coded token."""
    return find_records_by_search_term(conn, coded_term)


def search_records_with_emergency(
    conn: psycopg.Connection,
    expiry_manager: EmergencyExpiryManager,
    record_id: str,
    search_term: str,
) -> list[str]:
    """Search using the currently active emergency session."""
    coded_term = emergency_search_token(expiry_manager, record_id, search_term)
    return find_records_by_search_term(conn, coded_term)


def emergency_search_token(
    expiry_manager: EmergencyExpiryManager, record_id: str, search_term: str
) -> bytes:
    """The coded token for ``search_term`` under the record's live emergency key.

    Repository-agnostic, so the facility API never derives tokens itself
    (review F33). Raises if no session is live, exactly as the key lookup does.
    """
    emergency_key = expiry_manager.get_active_emergency_key(record_id)
    return derive_search_token(emergency_key, search_term)
