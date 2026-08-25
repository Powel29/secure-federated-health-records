"""Unidirectional ElGamal Proxy Re-Encryption (owner module: ``pre``, C3).

Provides key generation, proxy re-encryption key derivation (A -> B), ciphertext
re-encryption without plaintext exposure, and symmetric key encapsulation
(ARCHITECTURE.md §2 C3, ADR-0012).
"""

from __future__ import annotations

import secrets

from crypto_core.symmetric import hkdf_derive

from pre.exceptions import PREDecryptionError, PREKeyError

# Safe prime P = 2q + 1 where P and q are prime (256-bit safe prime from spike)
SAFE_PRIME_P = 0xF45C8BBE9322D813D2A0A92464E19D100A043DC1994F7CDC2A5D70D8D0F73667
SUBGROUP_ORDER_Q = (SAFE_PRIME_P - 1) // 2
GENERATOR_G = 4  # Quadratic residue generating the prime order-q subgroup

# Fixed HKDF context for symmetric-key encapsulation. A KDF salt and info string
# are domain-separation material, not secret key material, so pinning them to a
# constant is safe and does not violate the "never hardcode a key" rule
# (CONVENTIONS.md §2): recovery still requires the private key, never the salt.
_KDF_SALT = b"pre-key-encapsulation-salt"
_KDF_INFO = b"pre-symmetric-key"


def _rand_exponent() -> int:
    """Generate a random exponent in [2, SUBGROUP_ORDER_Q - 1]."""
    return secrets.randbelow(SUBGROUP_ORDER_Q - 2) + 2


def _is_subgroup_member(x: int) -> bool:
    """Return True if x is a non-trivial element of the prime-order-q subgroup.

    A caller-supplied group element (a public key, or the ``c1`` component of a
    ciphertext) that is not in the order-q subgroup enables small-subgroup
    confinement attacks against this hand-rolled ElGamal PRE. Every such element
    is checked before it is used in an exponentiation.
    """
    return 1 < x < SAFE_PRIME_P and pow(x, SUBGROUP_ORDER_Q, SAFE_PRIME_P) == 1


def generate_keypair() -> tuple[int, int]:
    """Generate a PRE private and public key pair.

    Returns:
        A tuple of ``(private_key_sk, public_key_pk)``.

    Security property:
        Private exponent is drawn from CSPRNG; public key is g^sk mod P.
    """
    sk = _rand_exponent()
    pk = pow(GENERATOR_G, sk, SAFE_PRIME_P)
    return sk, pk


def generate_rekey(sk_a: int, sk_b: int) -> int:
    """Generate unidirectional re-encryption key from delegator A to delegatee B.

    Computes rk_{A -> B} = sk_a * sk_b^-1 mod q.

    Args:
        sk_a: Delegator A's private key.
        sk_b: Delegatee B's private key.

    Returns:
        Re-encryption key integer rk.

    Raises:
        PREKeyError: If keys are out of bounds or not invertible.

    Security property:
        Re-key calculation is unidirectional (A -> B). The proxy holding rk cannot
        invert it to decrypt A's ciphertexts nor decrypt without B's private key.
    """
    if not (1 < sk_a < SUBGROUP_ORDER_Q) or not (1 < sk_b < SUBGROUP_ORDER_Q):
        raise PREKeyError("Private keys must be in valid subgroup exponent range")

    try:
        sk_b_inv = pow(sk_b, -1, SUBGROUP_ORDER_Q)
    except ValueError as exc:
        raise PREKeyError("sk_b is not invertible mod q") from exc

    return (sk_a * sk_b_inv) % SUBGROUP_ORDER_Q


def encrypt_point(pk: int, message_point: int) -> tuple[int, int]:
    """Encrypt a group element message_point under public key pk.

    Args:
        pk: Recipient's public key (in subgroup).
        message_point: Group element in [1, SAFE_PRIME_P - 1].

    Returns:
        Tuple of ciphertext components ``(c1, c2)``.

    Raises:
        PREKeyError: If the public key is not a valid subgroup element.
    """
    if not _is_subgroup_member(pk):
        raise PREKeyError("Public key is not a member of the order-q subgroup")

    k = _rand_exponent()
    c1 = pow(GENERATOR_G, k, SAFE_PRIME_P)
    c2 = (message_point * pow(pk, k, SAFE_PRIME_P)) % SAFE_PRIME_P
    return c1, c2


def reencrypt(rk: int, c1: int, c2: int) -> tuple[int, int]:
    """Transform ciphertext from A to B using re-encryption key rk.

    Computes c1' = c1^rk mod P; c2 remains unchanged.

    Args:
        rk: Re-encryption key rk_{A -> B}.
        c1: First ciphertext component.
        c2: Second ciphertext component.

    Returns:
        Transformed ciphertext tuple ``(c1_prime, c2)``.

    Security property:
        Proxy blindness: The proxy transforms the ciphertext without learning
        the underlying message or private keys (ADR-0012).

    Raises:
        PREKeyError: If c1 is not a valid subgroup element.
    """
    if not _is_subgroup_member(c1):
        raise PREKeyError(
            "Ciphertext component c1 is not a member of the order-q subgroup"
        )

    c1_prime = pow(c1, rk, SAFE_PRIME_P)
    return c1_prime, c2


def decrypt_point(sk: int, c1: int, c2: int) -> int:
    """Decrypt a ciphertext (original or re-encrypted) using private key sk.

    Computes m = c2 * (c1^-sk) mod P.

    Args:
        sk: Recipient's private key.
        c1: First ciphertext component.
        c2: Second ciphertext component.

    Returns:
        The recovered group element message_point.

    Raises:
        PREKeyError: If c1 is not a valid subgroup element.
        PREDecryptionError: If decryption fails.
    """
    if not _is_subgroup_member(c1):
        raise PREKeyError(
            "Ciphertext component c1 is not a member of the order-q subgroup"
        )

    try:
        c1_inv_sk = pow(c1, -sk, SAFE_PRIME_P)
        return (c2 * c1_inv_sk) % SAFE_PRIME_P
    except Exception as exc:
        raise PREDecryptionError(f"Failed to decrypt PRE point: {exc}") from exc


def encapsulate_key(pk: int) -> tuple[tuple[int, int], bytes]:
    """Encapsulate a fresh 256-bit symmetric key under public key pk.

    Args:
        pk: Public key of the recipient.

    Returns:
        A tuple of ``((c1, c2), symmetric_key_bytes)``.
    """
    # Random group point
    secret_exp = _rand_exponent()
    point = pow(GENERATOR_G, secret_exp, SAFE_PRIME_P)

    # Encrypt the group point
    c1, c2 = encrypt_point(pk, point)

    # Derive 32-byte symmetric key from the point using HKDF
    symmetric_key = hkdf_derive(
        ikm=point.to_bytes(32, byteorder="big"),
        salt=_KDF_SALT,
        info=_KDF_INFO,
        length=32,
    )

    return (c1, c2), symmetric_key


def decapsulate_key(sk: int, c1: int, c2: int) -> bytes:
    """Decapsulate the 256-bit symmetric key from ciphertext (c1, c2) using sk.

    Args:
        sk: Recipient's private key.
        c1: First ciphertext component.
        c2: Second ciphertext component.

    Returns:
        The 32-byte derived symmetric key.
    """
    point = decrypt_point(sk, c1, c2)
    return hkdf_derive(
        ikm=point.to_bytes(32, byteorder="big"),
        salt=_KDF_SALT,
        info=_KDF_INFO,
        length=32,
    )
