"""Unit tests for the search-token derivation and index-management surface.

These prove the construction is deterministic in ``(emergency_key, term)`` and
that ``index_search_term`` persists via the storage repository. The security
properties (attacker key does not match, plaintext not recoverable, documented
leakage) live in ``tests/security/test_phase2_search.py``.
"""

from __future__ import annotations

import secrets

from search import service


def test_same_key_and_term_derive_same_token() -> None:
    """Equality across derivations is the property that makes search work."""
    key = secrets.token_bytes(32)

    token1 = service.derive_search_token(key, "diabetes")
    token2 = service.derive_search_token(key, "diabetes")

    assert token1 == token2
    assert len(token1) == 32


def test_different_terms_derive_different_tokens() -> None:
    """Different plaintext terms must not collide under the same key."""
    key = secrets.token_bytes(32)

    diabetes_token = service.derive_search_token(key, "diabetes")
    cancer_token = service.derive_search_token(key, "cancer")

    assert diabetes_token != cancer_token


def test_different_keys_derive_different_tokens() -> None:
    """Two keys must never produce the same token for the same term.

    Nandini's original file had this test with no assertion; without it the
    'no plaintext leaks across keys' story has no evidence.
    """
    key_a = secrets.token_bytes(32)
    key_b = secrets.token_bytes(32)

    token_a = service.derive_search_token(key_a, "diabetes")
    token_b = service.derive_search_token(key_b, "diabetes")

    assert token_a != token_b


def test_index_search_term_persists_via_repository(monkeypatch) -> None:
    """``index_search_term`` calls ``insert_search_term`` with the derived token."""
    stored: dict[str, object] = {}

    def fake_insert(conn, record_id, coded_term):
        stored["conn"] = conn
        stored["record_id"] = record_id
        stored["coded_term"] = coded_term

    monkeypatch.setattr("search.service.insert_search_term", fake_insert)

    key = secrets.token_bytes(32)
    conn_sentinel = object()

    token = service.index_search_term(conn_sentinel, "rec-123", key, "diabetes")

    assert stored["conn"] is conn_sentinel
    assert stored["record_id"] == "rec-123"
    assert stored["coded_term"] == token
    assert token == service.derive_search_token(key, "diabetes")


def test_search_records_delegates_to_repository(monkeypatch) -> None:
    """``search_records`` returns exactly what the repository returns."""
    captured: dict[str, object] = {}

    def fake_find(conn, coded_term):
        captured["conn"] = conn
        captured["coded_term"] = coded_term
        return ["rec-1", "rec-2"]

    monkeypatch.setattr("search.service.find_records_by_search_term", fake_find)

    conn_sentinel = object()
    result = service.search_records(conn_sentinel, b"opaque")

    assert result == ["rec-1", "rec-2"]
    assert captured == {"conn": conn_sentinel, "coded_term": b"opaque"}
