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

from search.service import derive_search_token


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
