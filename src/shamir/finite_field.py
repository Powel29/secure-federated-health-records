"""Finite field arithmetic over prime field GF(P) for Shamir secret sharing (C2).

Uses the 257-bit safe prime P = 2^256 + 297, which is strictly greater than 2^256 - 1,
allowing any 256-bit secret block to be embedded directly as a field element.
"""

from __future__ import annotations

import secrets

# P is prime: 2^256 + 297
PRIME_MODULUS = (1 << 256) + 297
BLOCK_SIZE = 32  # 256 bits per block
SHARE_BYTES_PER_BLOCK = 33  # 257-bit field element serialized to 33 bytes


def rand_field_element() -> int:
    """Generate a uniform random field element in [0, PRIME_MODULUS - 1].

    Returns:
        A random integer field element.

    Security property:
        Coefficients for the sharing polynomial are drawn uniformly at random
        from the CSPRNG (CONVENTIONS.md §2 rule 2).
    """
    return secrets.randbelow(PRIME_MODULUS)


def mod_inv(a: int) -> int:
    """Compute modular inverse a^-1 mod PRIME_MODULUS.

    Args:
        a: Non-zero field element.

    Returns:
        The modular inverse.

    Raises:
        ValueError: If a is zero mod PRIME_MODULUS.
    """
    a = a % PRIME_MODULUS
    if a == 0:
        raise ValueError("Cannot invert zero in finite field")
    return pow(a, -1, PRIME_MODULUS)


def eval_polynomial(coefficients: list[int], x: int) -> int:
    """Evaluate polynomial f(x) = sum(coefficients[i] * x^i) mod PRIME_MODULUS.

    Args:
        coefficients: Polynomial coefficients with constant term at index 0.
        x: The evaluation point (x != 0 for shares).

    Returns:
        The field element value f(x).
    """
    result = 0
    for power, coeff in enumerate(coefficients):
        result = (result + coeff * pow(x, power, PRIME_MODULUS)) % PRIME_MODULUS
    return result


def lagrange_interpolate_zero(points: list[tuple[int, int]]) -> int:
    """Reconstruct f(0) using Lagrange interpolation at x = 0.

    Args:
        points: A list of k tuples (x_i, y_i) where x_i are distinct non-zero integers.

    Returns:
        The constant term f(0) mod PRIME_MODULUS.
    """
    k = len(points)
    secret = 0
    for i in range(k):
        xi, yi = points[i]
        num = 1
        den = 1
        for j in range(k):
            if i == j:
                continue
            xj, _ = points[j]
            num = (num * (-xj)) % PRIME_MODULUS
            den = (den * (xi - xj)) % PRIME_MODULUS
        lagrange_coeff = (num * mod_inv(den)) % PRIME_MODULUS
        secret = (secret + yi * lagrange_coeff) % PRIME_MODULUS
    return secret
