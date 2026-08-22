"""P0-6 crypto sanity spike (throwaway) -- owner: Avaneeth.

Standalone script, NOT a pytest suite. Run it on each machine::

    python tests/spike_crypto_sanity.py

It exercises the four primitives the project depends on and exits 0 iff every one
round-trips; any failure prints FAIL and exits non-zero. The filename is
deliberately not ``test_*`` so pytest never collects it -- it is a sanity spike,
not a regression test.

The direct ``cryptography.hazmat`` imports below are the one justified exception
to CONVENTIONS.md §2 rule 1 ("all crypto goes through crypto_core"): this spike
exists to validate the raw primitives *before* crypto_core wraps them (ADR-0001),
so there is nothing to route through yet. Module code must still obey rule 1.
"""

from __future__ import annotations

import os
import secrets
import sys
from collections.abc import Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

Check = tuple[str, bool]


def aesgcm_checks() -> list[Check]:
    """AES-256-GCM: authenticated round-trip, and tamper detection."""
    key = secrets.token_bytes(32)  # 256-bit key from a CSPRNG, never `random`
    nonce = os.urandom(12)  # 96-bit GCM nonce (contracts.GCM_NONCE_BYTES)
    aad = b"record-id:demo"
    plaintext = b"synthetic record -- no real PHI, ever"

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    round_trip = AESGCM(key).decrypt(nonce, ciphertext, aad) == plaintext

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    tamper_rejected = False
    try:
        AESGCM(key).decrypt(nonce, bytes(tampered), aad)
    except InvalidTag:
        tamper_rejected = True

    return [
        ("encrypt/decrypt round-trip", round_trip),
        ("tampered ciphertext rejected", tamper_rejected),
    ]


def hkdf_checks() -> list[Check]:
    """HKDF-SHA256: deterministic per (ikm, salt, info); context-separated."""
    ikm = secrets.token_bytes(32)
    salt = os.urandom(16)

    def derive(info: bytes) -> bytes:
        # HKDF instances are single-use, so build a fresh one per derivation.
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(
            ikm
        )

    deterministic = derive(b"context-1") == derive(b"context-1")
    context_separated = derive(b"context-1") != derive(b"context-2")

    return [
        ("deterministic derivation", deterministic),
        ("distinct info -> distinct key", context_separated),
    ]


def ecdsa_checks() -> list[Check]:
    """ECDSA on P-256: sign/verify, tamper rejection, PEM key I/O."""
    algorithm = ec.ECDSA(hashes.SHA256())
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    message = b"emergency-assertion canonical bytes"
    signature = private_key.sign(message, algorithm)

    verified = True
    try:
        public_key.verify(signature, message, algorithm)
    except InvalidSignature:
        verified = False

    tamper_rejected = False
    try:
        public_key.verify(signature, message + b"!", algorithm)
    except InvalidSignature:
        tamper_rejected = True

    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    reloaded = serialization.load_pem_public_key(pem)
    pem_round_trip = True
    try:
        reloaded.verify(signature, message, algorithm)
    except InvalidSignature:
        pem_round_trip = False

    return [
        ("sign/verify round-trip", verified),
        ("tampered message rejected", tamper_rejected),
        ("PEM key serialization", pem_round_trip),
    ]


# Verified 256-bit safe prime p = 2q + 1 with q prime; g = 4 is a quadratic
# residue and so generates the order-q subgroup. TOY parameters for a sanity
# check only -- the real `pre` module (P1-5) uses production sizing and
# constant-time operations. Test-only material (CONVENTIONS.md §2 rule 4).
_P = 0xF45C8BBE9322D813D2A0A92464E19D100A043DC1994F7CDC2A5D70D8D0F73667
_Q = (_P - 1) // 2
_G = 4


def _rand_exponent() -> int:
    """A random exponent in [2, q-1]; invertible mod q since q is prime."""
    return secrets.randbelow(_Q - 2) + 2


def pre_checks() -> list[Check]:
    """Unidirectional ElGamal-style PRE (ARCHITECTURE.md §2 C3), one direction A->B.

    Re-key is ``rk = a * b^-1 mod q`` -- note the order: ``b * a^-1`` would NOT
    decrypt for B. Inverses are taken mod the subgroup order q, not p-1 (only
    then is every nonzero exponent invertible). The proxy transforms the
    ciphertext using rk and the public ciphertext only; it never sees plaintext.
    """
    a, b = _rand_exponent(), _rand_exponent()
    pk_a = pow(_G, a, _P)

    message = pow(_G, _rand_exponent(), _P)  # a subgroup element stands in for m
    k = _rand_exponent()
    c1 = pow(_G, k, _P)
    c2 = (message * pow(pk_a, k, _P)) % _P

    recovered_a = (c2 * pow(c1, -a, _P)) % _P  # A decrypts with its own key

    rk = (a * pow(b, -1, _Q)) % _Q  # a * b^-1 mod q  (unidirectional A -> B)
    c1_re = pow(c1, rk, _P)
    recovered_b = (c2 * pow(c1_re, -b, _P)) % _P  # B decrypts the re-wrapped ct

    # The proxy holds rk + ciphertext but not b: applying the transform without
    # B's secret key must NOT yield the plaintext -- rk alone reveals nothing.
    proxy_blind = (c2 * pow(c1_re, -1, _P)) % _P != message

    return [
        ("encrypt/decrypt (A)", recovered_a == message),
        ("re-encrypt A->B transforms ct", c1_re != c1),
        ("decrypt as B", recovered_b == message),
        ("re-key alone reveals no plaintext", proxy_blind),
    ]


def main() -> int:
    """Run every section; return 0 iff all checks pass."""
    sections: list[tuple[str, Callable[[], list[Check]]]] = [
        ("AES-256-GCM", aesgcm_checks),
        ("HKDF-SHA256", hkdf_checks),
        ("ECDSA P-256", ecdsa_checks),
        ("Toy ElGamal PRE (unidirectional A->B)", pre_checks),
    ]

    failures = 0
    for title, run in sections:
        print(f"=== {title} ===")
        for label, ok in run():
            status = "PASS" if ok else "FAIL"
            leader = "." * max(3, 34 - len(label))
            print(f"  {label} {leader} {status}")
            failures += 0 if ok else 1
        print()

    if failures:
        print(f"CHECKS FAILED ({failures})")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
