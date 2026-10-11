"""Tests for Shamir secret sharing (C2)."""

from __future__ import annotations

import secrets

import pytest
from shamir.exceptions import (
    DuplicateShareError,
    InsufficientSharesError,
    InvalidShareError,
)
from shamir.finite_field import PRIME_MODULUS, SHARE_BYTES_PER_BLOCK
from shamir.split import combine_shares, split_secret


def test_shamir_2_of_3_reconstruct() -> None:
    """Any 2 of 3 shares must reconstruct the exact original secret."""
    secret = secrets.token_bytes(32)
    shares = split_secret(secret, k=2, n=3)
    assert len(shares) == 3

    # Reconstruct from (1, 2)
    rec_12 = combine_shares([shares[0], shares[1]], k=2)
    assert rec_12 == secret

    # Reconstruct from (2, 3)
    rec_23 = combine_shares([shares[1], shares[2]], k=2)
    assert rec_23 == secret

    # Reconstruct from (1, 3)
    rec_13 = combine_shares([shares[0], shares[2]], k=2)
    assert rec_13 == secret


def test_shamir_3_of_5_reconstruct() -> None:
    """Any 3 of 5 shares must reconstruct the secret."""
    secret = b"Arbitrary length secret string for federation testing!"
    shares = split_secret(secret, k=3, n=5)
    assert len(shares) == 5

    # Any subset of 3
    rec = combine_shares([shares[0], shares[2], shares[4]], k=3)
    assert rec == secret


def test_shamir_insufficient_shares_rejected() -> None:
    """Reconstructing with fewer than k shares must fail closed."""
    secret = secrets.token_bytes(32)
    shares = split_secret(secret, k=3, n=5)

    with pytest.raises(InsufficientSharesError):
        combine_shares(shares[:2], k=3)


def test_shamir_duplicate_shares_rejected() -> None:
    """Reconstructing with duplicate shares must be rejected."""
    secret = secrets.token_bytes(32)
    shares = split_secret(secret, k=2, n=3)

    with pytest.raises(DuplicateShareError):
        combine_shares([shares[0], shares[0]], k=2)


def test_shamir_corrupted_share_bytes_rejected() -> None:
    """Corrupted share bytes must fail closed."""
    secret = secrets.token_bytes(32)
    shares = split_secret(secret, k=2, n=3)

    corrupted_share = (shares[0][0], shares[0][1][:-1])  # truncated share
    with pytest.raises(InvalidShareError):
        combine_shares([corrupted_share, shares[1]], k=2)


def test_shamir_invalid_threshold_parameters() -> None:
    """Invalid k or n must raise ValueError."""
    secret = secrets.token_bytes(16)

    with pytest.raises(ValueError):
        split_secret(secret, k=0, n=3)

    with pytest.raises(ValueError):
        split_secret(secret, k=4, n=3)


def test_share_index_aliasing_rejected():
    """F27: x and x + P are the same field point and must not combine."""

    secret = b"\x42" * 32
    shares = split_secret(secret, k=2, n=3)
    assert combine_shares(shares[:2], k=2) == secret  # setup is valid
    x, share = shares[0]
    with pytest.raises(InvalidShareError, match="outside"):
        combine_shares([(x, share), (x + PRIME_MODULUS, share)], k=2)


def test_share_at_x_zero_rejected():
    """F27: x = 0 is where the secret sits; no share may claim it."""

    shares = split_secret(b"\x42" * 32, k=2, n=3)
    with pytest.raises(InvalidShareError, match="outside"):
        combine_shares([(0, shares[0][1]), shares[1]], k=2)


def test_share_value_outside_field_rejected():
    """F27: a y-value >= P is not a field element and must be refused."""

    shares = split_secret(b"\x42" * 32, k=2, n=3)
    too_big = b"\xff" * SHARE_BYTES_PER_BLOCK + shares[0][1][SHARE_BYTES_PER_BLOCK:]
    with pytest.raises(InvalidShareError, match="field element"):
        combine_shares([(shares[0][0], too_big), shares[1]], k=2)
