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
from shamir.split import combine_shares, split_secret


def test_sec_single_share_reveals_no_secret() -> None:
    """Security property: 1 share of a 2-of-3 threshold reveals zero information."""
    secret = secrets.token_bytes(32)
    shares = split_secret(secret, k=2, n=3)

    # 1 share cannot reconstruct
    with pytest.raises(InsufficientSharesError):
        combine_shares([shares[0]], k=2)


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


def test_sec_pre_proxy_cannot_decapsulate_without_private_key() -> None:
    """Security property: Proxy with rk cannot decapsulate key without sk_B."""
    sk_a, pk_a = generate_keypair()
    sk_b, pk_b = generate_keypair()
    wrong_sk, _ = generate_keypair()

    (c1, c2), sym_key = encapsulate_key(pk_a)
    rk = generate_rekey(sk_a, sk_b)
    c1_re, c2_re = reencrypt(rk, c1, c2)

    # Proxy holding re-encrypted ciphertext cannot decapsulate with arbitrary key
    wrong_key = decapsulate_key(wrong_sk, c1_re, c2_re)
    assert wrong_key != sym_key
