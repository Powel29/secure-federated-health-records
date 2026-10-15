"""Tests for Proxy Re-Encryption (C3)."""

from __future__ import annotations

import secrets

import pytest
from pre.elgamal import (
    GENERATOR_G,
    SAFE_PRIME_P,
    SUBGROUP_ORDER_Q,
    decapsulate_key,
    decrypt_point,
    encapsulate_key,
    encrypt_point,
    generate_keypair,
    generate_rekey,
    reencrypt,
)
from pre.exceptions import PREKeyError

# (P - 1) == -1 mod P is a well-formed field element (1 < x < P) of order 2,
# so it is a valid stand-in for a hostile non-subgroup group element.
_NON_SUBGROUP_ELEMENT = SAFE_PRIME_P - 1


def test_pre_encrypt_decrypt_original_recipient() -> None:
    """Original recipient A can decrypt their own ciphertext."""
    sk_a, pk_a = generate_keypair()
    m = pow(GENERATOR_G, secrets.randbelow(SUBGROUP_ORDER_Q - 2) + 2, SAFE_PRIME_P)

    c1, c2 = encrypt_point(pk_a, m)
    recovered = decrypt_point(sk_a, c1, c2)
    assert recovered == m


def test_pre_reencryption_and_delegatee_decryption() -> None:
    """Ciphertext transformed with re-encryption key rk_{A->B} decrypts under sk_B."""
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()

    m = pow(GENERATOR_G, secrets.randbelow(SUBGROUP_ORDER_Q - 2) + 2, SAFE_PRIME_P)
    c1, c2 = encrypt_point(pk_a, m)

    rk_a_to_b = generate_rekey(sk_a, sk_b)
    c1_prime, c2_prime = reencrypt(rk_a_to_b, c1, c2)

    # c1 is transformed
    assert c1_prime != c1
    assert c2_prime == c2

    # Recipient B decrypts the transformed ciphertext
    recovered_b = decrypt_point(sk_b, c1_prime, c2_prime)
    assert recovered_b == m


def test_pre_proxy_blindness() -> None:
    """Proxy holding rk_{A->B} cannot recover plaintext without sk_B."""
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()

    m = pow(GENERATOR_G, secrets.randbelow(SUBGROUP_ORDER_Q - 2) + 2, SAFE_PRIME_P)
    c1, c2 = encrypt_point(pk_a, m)

    rk_a_to_b = generate_rekey(sk_a, sk_b)
    c1_prime, c2_prime = reencrypt(rk_a_to_b, c1, c2)

    # An unauthorized party or the proxy cannot obtain m directly
    wrong_sk, _ = generate_keypair()
    unauthorized = decrypt_point(wrong_sk, c1_prime, c2_prime)
    assert unauthorized != m


def test_pre_symmetric_key_encapsulation_round_trip() -> None:
    """Encapsulated symmetric key decapsulates cleanly before and after PRE."""
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()

    (c1, c2), sym_key = encapsulate_key(pk_a)
    assert len(sym_key) == 32

    # A decapsulates
    decaps_a = decapsulate_key(sk_a, c1, c2)
    assert decaps_a == sym_key

    # Transform to B
    rk = generate_rekey(sk_a, sk_b)
    c1_re, c2_re = reencrypt(rk, c1, c2)

    # B decapsulates
    decaps_b = decapsulate_key(sk_b, c1_re, c2_re)
    assert decaps_b == sym_key


def test_encrypt_point_rejects_non_subgroup_public_key() -> None:
    """A public key outside the order-q subgroup is refused (small-subgroup guard).

    Backs the claim: caller-supplied group elements are validated for subgroup
    membership before any exponentiation, closing off small-subgroup confinement.
    """
    m = pow(GENERATOR_G, secrets.randbelow(SUBGROUP_ORDER_Q - 2) + 2, SAFE_PRIME_P)
    with pytest.raises(PREKeyError):
        encrypt_point(_NON_SUBGROUP_ELEMENT, m)


def test_reencrypt_rejects_non_subgroup_c1() -> None:
    """A ciphertext c1 outside the order-q subgroup is refused before re-wrapping."""
    sk_a, _ = generate_keypair()
    sk_b, _ = generate_keypair()
    rk = generate_rekey(sk_a, sk_b)
    with pytest.raises(PREKeyError):
        reencrypt(rk, _NON_SUBGROUP_ELEMENT, c2=12345)


def test_decrypt_point_rejects_non_subgroup_c1() -> None:
    """A ciphertext c1 outside the order-q subgroup is refused before decryption."""
    sk, _ = generate_keypair()
    with pytest.raises(PREKeyError):
        decrypt_point(sk, _NON_SUBGROUP_ELEMENT, c2=12345)


def test_rekey_inverts_to_the_reverse_direction() -> None:
    """ADR-0071 (review D11-a): the scheme is bidirectional, and says so.

    Whoever holds rk_{A->B} computes rk^-1 mod q, which is rk_{B->A}: a
    ciphertext for B re-encrypted with it decrypts under A's key. This test
    documents the limitation the paper states; it is not a property we want.
    """
    sk_a, _pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()
    m = pow(GENERATOR_G, secrets.randbelow(SUBGROUP_ORDER_Q - 2) + 2, SAFE_PRIME_P)

    rk_a_to_b = generate_rekey(sk_a, sk_b)
    rk_b_to_a = pow(rk_a_to_b, -1, SUBGROUP_ORDER_Q)
    assert rk_b_to_a == generate_rekey(sk_b, sk_a)

    c1, c2 = encrypt_point(pk_b, m)
    assert decrypt_point(sk_a, *reencrypt(rk_b_to_a, c1, c2)) == m
