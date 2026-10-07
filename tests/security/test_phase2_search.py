"""Negative security tests for the P2-5 encrypted search index (CONVENTIONS §5).

Backs the P2-5 done-when in WORKFLOW.md: "the index is searchable but the server
learns no plaintext words." Each test names the paper claim it evidences in its
docstring so the security-analysis section is a mechanical mapping.

The time-boxed dead-after-expiry test lives with P3-8 (it needs the emergency
lifecycle wired up); the tests here cover the properties that hold at P2-5:
key-scoping, plaintext non-recoverability, and the documented deterministic-SSE
leakage that the paper must cite as a known limitation.
"""

from __future__ import annotations

import secrets

import pytest
from crypto_core import generate_ec_keypair
from lifecycle.exceptions import EmergencySessionExpiredError
from lifecycle.expiry import EmergencyExpiryManager
from search.service import derive_search_token, search_records_with_emergency


def test_sec_search_token_from_wrong_emergency_key_does_not_match() -> None:
    """Security property: tokens are scoped to the emergency key.

    Backs the P2-5 claim that "the server learns no plaintext words." An
    attacker who observes a stored coded_term and correctly guesses the
    plaintext term cannot reproduce it without the emergency key: any other
    key -- including one that differs in a single byte -- yields a different
    token, so the guess cannot be confirmed by comparing bytes.
    """
    real_key = secrets.token_bytes(32)
    attacker_key = secrets.token_bytes(32)

    # Positive control: with the real key, the same term reproduces the token.
    stored = derive_search_token(real_key, "diabetes")
    reproduced = derive_search_token(real_key, "diabetes")
    assert stored == reproduced, "same-key reproduction is broken; test is invalid"

    # Negative: a token derived under any other key does not match the stored one.
    attacker_token = derive_search_token(attacker_key, "diabetes")
    assert attacker_token != stored


def test_sec_plaintext_term_not_recoverable_from_coded_token() -> None:
    """Security property: the coded_term bytes do not contain the plaintext term.

    Backs P2-5's "server learns no plaintext words" against the class of
    regression where a future refactor stores the plaintext concatenated
    to a hash, or leaks it in the token's low bytes.
    """
    key = secrets.token_bytes(32)
    term = "diabetes-mellitus-type-2"
    token = derive_search_token(key, term)

    # Positive control: derivation ran (32 bytes of HKDF output).
    assert len(token) == 32

    # Negative: no 4-byte substring of the plaintext term appears in the
    # token bytes. HKDF output is indistinguishable from random, so this
    # would only fire on a regression that stopped calling the KDF.
    term_bytes = term.encode("utf-8")
    for start in range(len(term_bytes) - 3):
        assert term_bytes[start : start + 4] not in token


def test_sec_documented_leakage_same_term_same_key_yields_equal_tokens() -> None:
    """Documented leakage: this scheme is deterministic searchable encryption.

    Two records that index the same plaintext term produce identical
    coded_terms. The store can observe which records share which coded
    values -- the standard search-pattern / access-pattern leakage of
    symmetric SSE. This is intrinsic to equality-searchable encryption
    without oblivious RAM, and the paper cites it as a known limitation
    (docs/adr/0027-search-token-construction.md).

    This test exists so that any future construction change that silently
    breaks the equality property (which is the *feature* enabling search)
    is caught in CI, not by a user whose search stops returning matches.
    """
    key = secrets.token_bytes(32)

    token_a = derive_search_token(key, "diabetes")
    token_b = derive_search_token(key, "diabetes")

    assert token_a == token_b


@pytest.mark.claim("C4", level="module")
def test_sec_emergency_search_stops_after_expiry(monkeypatch) -> None:
    """P3-8: emergency search works before expiry and fails after expiry."""
    from datetime import datetime, timedelta, timezone

    class FakeClock:
        def __init__(self):
            self.now = datetime.now(timezone.utc)

        def __call__(self):
            return self.now

        def advance(self, seconds):
            self.now += timedelta(seconds=seconds)

    clock = FakeClock()
    manager = EmergencyExpiryManager(
        signing_key=generate_ec_keypair()[0],
        clock=clock,
    )

    record_id = "rec-p3-8"
    emergency_key = secrets.token_bytes(32)

    manager._sessions[record_id] = type(
        "Session",
        (),
        {
            "emergency_key": emergency_key,
            "expires_at": clock.now + timedelta(seconds=5),
            "is_expired": lambda self, now: now >= self.expires_at,
        },
    )()

    monkeypatch.setattr(
        "search.service.find_records_by_search_term",
        lambda conn, coded_term: ["rec-p3-8"],
    )

    result = search_records_with_emergency(
        None,
        manager,
        record_id,
        "diabetes",
    )
    assert result == ["rec-p3-8"]

    clock.advance(5)

    with pytest.raises(EmergencySessionExpiredError):
        search_records_with_emergency(
            None,
            manager,
            record_id,
            "diabetes",
        )
