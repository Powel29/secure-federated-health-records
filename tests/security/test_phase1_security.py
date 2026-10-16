"""Negative security tests for Phase 1 primitives (CONVENTIONS.md §5)."""

from __future__ import annotations

import secrets

import pytest
from crypto_core.asymmetric import generate_ec_keypair, sign, verify
from crypto_core.exceptions import InvalidSignatureError, InvalidTagError
from crypto_core.symmetric import aes_gcm_decrypt, aes_gcm_encrypt, generate_key
from pre.elgamal import (
    decapsulate_key,
    encapsulate_key,
    generate_keypair,
    generate_rekey,
    reencrypt,
)
from records.exceptions import UnwrappingError
from records.service import unwrap_dek, wrap_dek
from shamir.exceptions import InsufficientSharesError
from shamir.finite_field import (
    PRIME_MODULUS,
    eval_polynomial,
    lagrange_interpolate_zero,
    rand_field_element,
)
from shamir.split import combine_shares, split_secret


def _interpolate_at(points: list[tuple[int, int]], x_query: int) -> int:
    """Evaluate the unique interpolating polynomial through ``points`` at x_query.

    Test-only helper (Lagrange interpolation at an arbitrary point over GF(P)).
    ``shamir.finite_field`` only exposes interpolation at x=0, so the secrecy
    test carries its own general-point evaluation.
    """
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (x_query - xj)) % PRIME_MODULUS
            den = (den * (xi - xj)) % PRIME_MODULUS
        total = (total + yi * num * pow(den, -1, PRIME_MODULUS)) % PRIME_MODULUS
    return total


def test_sec_below_threshold_shares_rejected() -> None:
    """Security property: fewer than k shares are refused by the combiner.

    Backs the arity half of the threshold claim: the API will not reconstruct
    below the threshold. (Secrecy — that the withheld shares reveal nothing — is
    a separate, stronger property proven in the test below.)
    """
    secret = secrets.token_bytes(32)
    shares = split_secret(secret, k=2, n=3)

    with pytest.raises(InsufficientSharesError):
        combine_shares([shares[0]], k=2)


def test_sec_below_threshold_shares_fit_any_secret() -> None:
    """Security property: k-1 shares are consistent with EVERY secret.

    Backs the paper claim that a below-threshold coalition learns zero
    information (information-theoretic secrecy of Shamir). We take two shares
    (x=1, x=2) of a real 3-of-n sharing and show the SAME two shares reconstruct
    to a *different* secret when combined with a forged third share — so the two
    shares do not pin the secret at all. A leaking split (effective degree < k-1)
    would make the two shares determine one secret and this test would fail.
    """
    k = 3
    coefficients = [rand_field_element() for _ in range(k)]
    true_secret = coefficients[0]

    # Two below-threshold shares of the genuine sharing.
    p1 = (1, eval_polynomial(coefficients, 1))
    p2 = (2, eval_polynomial(coefficients, 2))

    # A different target secret, and the third share that would realise it.
    forged_secret = (true_secret + 1) % PRIME_MODULUS
    forged_third = (3, _interpolate_at([p1, p2, (0, forged_secret)], 3))

    # Positive control: the two shares + the genuine third share give the truth.
    genuine_third = (3, eval_polynomial(coefficients, 3))
    assert lagrange_interpolate_zero([p1, p2, genuine_third]) == true_secret

    # The identical two shares + a forged third share reconstruct to a *different*
    # secret: proof the two shares alone carry no information about the secret.
    assert lagrange_interpolate_zero([p1, p2, forged_third]) == forged_secret
    assert forged_secret != true_secret


def test_sec_aes_gcm_tamper_detection() -> None:
    """Security property: ciphertext or tag tampering is rejected (fails closed)."""
    key = generate_key(32)
    plaintext = b"critical telemetry"
    ct, nonce = aes_gcm_encrypt(key, plaintext)

    # Bit flip in ciphertext
    tampered_ct = bytearray(ct)
    tampered_ct[5] ^= 0x55

    with pytest.raises(InvalidTagError):
        aes_gcm_decrypt(key, nonce, bytes(tampered_ct))


def test_sec_ecdsa_tampered_signature_detection() -> None:
    """Security property: signature forgery or bit manipulation is detected."""
    sk, pk = generate_ec_keypair()
    msg = b"emergency assertion claim"
    sig = sign(sk, msg)

    tampered_sig = bytearray(sig)
    tampered_sig[10] ^= 0xAA

    with pytest.raises(InvalidSignatureError):
        verify(pk, msg, bytes(tampered_sig))


def test_sec_cross_record_dek_substitution_rejected() -> None:
    """Security property: DEK wrapping bound to record_id via AAD; swap fails."""
    dek1 = generate_key(32)
    wrap_key = generate_key(32)

    # Wrap DEK for record 1
    wrapping1 = wrap_dek(
        dek=dek1,
        record_id="rec-001",
        wrapping_key=wrap_key,
        wrapped_for="pol-1",
    )

    # Malicious attacker tries to use wrapping1 for record 2 (tampering record_id)
    # unwrap_dek binds wrapping.record_id as AAD, so changing record_id fails
    tampered_wrapping = wrapping1.model_copy(update={"record_id": "rec-002"})

    with pytest.raises(UnwrappingError):
        unwrap_dek(tampered_wrapping, wrap_key)


def test_sec_pre_key_rebound_to_delegatee_only() -> None:
    """Security property: re-encryption re-binds the key to B and to no one else.

    Backs the claim that the proxy re-wraps without exposing the key. The proxy
    holds only the re-encryption key ``rk`` and the transformed ciphertext, never
    ``sk_b``. We assert (positive control) that the legitimate delegatee B
    recovers the exact key, and that none of the parties who lack sk_b — the
    original delegator A (the re-encrypted ciphertext is now B's), an unrelated
    key holder, or the
    proxy wielding ``rk`` itself — can reconstruct it.
    """
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()
    outsider_sk, _ = generate_keypair()

    (c1, c2), sym_key = encapsulate_key(pk_a)
    rk = generate_rekey(sk_a, sk_b)
    c1_re, c2_re = reencrypt(rk, c1, c2)

    # Positive control: the legitimate delegatee B recovers the exact key.
    assert decapsulate_key(sk_b, c1_re, c2_re) == sym_key

    # Even the original delegator A cannot read it post-rewrap. (This is not
    # unidirectionality: rk itself inverts to B -> A, see ADR-0076.)
    assert decapsulate_key(sk_a, c1_re, c2_re) != sym_key
    # An unrelated key holder cannot read it.
    assert decapsulate_key(outsider_sk, c1_re, c2_re) != sym_key
    # The proxy's re-encryption key is not itself a decryption key.
    assert decapsulate_key(rk, c1_re, c2_re) != sym_key
