"""Shamir (k, n) threshold secret sharing implementation (C2).

Enables splitting a secret into n shares such that any k shares can reconstruct it,
while any k-1 shares reveal zero information about the secret.
"""

from __future__ import annotations

import struct

from shamir.exceptions import (
    DuplicateShareError,
    InsufficientSharesError,
    InvalidShareError,
    SecretSharingError,
)
from shamir.finite_field import (
    BLOCK_SIZE,
    PRIME_MODULUS,
    SHARE_BYTES_PER_BLOCK,
    eval_polynomial,
    lagrange_interpolate_zero,
    rand_field_element,
)


def split_secret(secret: bytes, k: int, n: int) -> list[tuple[int, bytes]]:
    """Split an arbitrary byte secret into n shares with threshold k.

    Args:
        secret: Secret bytes to split.
        k: Threshold number of shares required to reconstruct (k >= 1).
        n: Total number of shares to produce (n >= k).

    Returns:
        A list of n tuples ``(x, share_bytes)`` for x in 1..n.

    Raises:
        ValueError: If k < 1 or n < k or n >= PRIME_MODULUS.

    Security property:
        Information-theoretic security: any subset of fewer than k shares reveals
        zero information about the secret.
    """
    if k < 1:
        raise ValueError(f"Threshold k must be >= 1, got {k}")
    if n < k:
        raise ValueError(f"Total shares n must be >= threshold k ({k}), got {n}")
    if n >= PRIME_MODULUS:
        raise ValueError(f"Total shares n must be < prime modulus, got {n}")

    # Pack secret length (4-byte big-endian) + secret payload
    payload = struct.pack(">I", len(secret)) + secret
    # Pad to multiple of BLOCK_SIZE (32 bytes)
    remainder = len(payload) % BLOCK_SIZE
    if remainder != 0:
        padding_needed = BLOCK_SIZE - remainder
        payload = payload + b"\x00" * padding_needed

    num_blocks = len(payload) // BLOCK_SIZE

    # Each share x will accumulate SHARE_BYTES_PER_BLOCK bytes per block
    share_buffers: dict[int, bytearray] = {x: bytearray() for x in range(1, n + 1)}

    for b in range(num_blocks):
        block_bytes = payload[b * BLOCK_SIZE : (b + 1) * BLOCK_SIZE]
        secret_int = int.from_bytes(block_bytes, byteorder="big")

        # Polynomial of degree k - 1 with constant term secret_int
        coefficients = [secret_int] + [rand_field_element() for _ in range(k - 1)]

        for x in range(1, n + 1):
            y = eval_polynomial(coefficients, x)
            share_buffers[x].extend(y.to_bytes(SHARE_BYTES_PER_BLOCK, byteorder="big"))

    return [(x, bytes(share_buffers[x])) for x in range(1, n + 1)]


def combine_shares(shares: list[tuple[int, bytes]], k: int | None = None) -> bytes:
    """Reconstruct a secret from a list of k or more distinct shares.

    Args:
        shares: List of tuples ``(x, share_bytes)``.
        k: Expected threshold (if specified, enforces len(shares) >= k).

    Returns:
        The reconstructed secret bytes.

    Raises:
        InsufficientSharesError: If fewer than k shares are provided.
        DuplicateShareError: If duplicate x-coordinates are detected.
        InvalidShareError: If share byte lengths are inconsistent or corrupted.
        SecretSharingError: If payload cannot be unpacked.

    Security property:
        Fails closed on corrupted, duplicate, or insufficient shares.
    """
    if not shares:
        raise InsufficientSharesError("No shares provided for secret reconstruction")

    if k is not None and len(shares) < k:
        raise InsufficientSharesError(
            f"Expected at least {k} shares, received {len(shares)}"
        )

    # Check for duplicate x coordinates
    seen_x: set[int] = set()
    for x, _ in shares:
        if x in seen_x:
            raise DuplicateShareError(f"Duplicate share with x={x} detected")
        seen_x.add(x)

    # Take the first k shares if k is specified, else take all unique shares
    eval_shares = shares[:k] if k is not None else shares
    if len(eval_shares) < 1:
        raise InsufficientSharesError("Need at least 1 share")

    # Verify all share byte lengths match and are multiples of SHARE_BYTES_PER_BLOCK
    first_len = len(eval_shares[0][1])
    if first_len == 0 or first_len % SHARE_BYTES_PER_BLOCK != 0:
        raise InvalidShareError(
            f"Invalid share length: {first_len} is not a multiple of block size"
        )

    for x, s_bytes in eval_shares:
        if len(s_bytes) != first_len:
            raise InvalidShareError(
                f"Mismatched share length for x={x}: expected {first_len}"
            )

    num_blocks = first_len // SHARE_BYTES_PER_BLOCK
    reconstructed_payload = bytearray()

    for b in range(num_blocks):
        points: list[tuple[int, int]] = []
        for x, s_bytes in eval_shares:
            chunk = s_bytes[b * SHARE_BYTES_PER_BLOCK : (b + 1) * SHARE_BYTES_PER_BLOCK]
            y = int.from_bytes(chunk, byteorder="big")
            points.append((x, y))

        secret_int = lagrange_interpolate_zero(points)
        try:
            block_bytes = secret_int.to_bytes(BLOCK_SIZE, byteorder="big")
        except OverflowError as exc:
            raise InvalidShareError("Reconstructed block exceeded block size") from exc
        reconstructed_payload.extend(block_bytes)

    # Unpack length prefix
    if len(reconstructed_payload) < 4:
        raise SecretSharingError("Reconstructed payload is too short for length prefix")

    (secret_len,) = struct.unpack(">I", bytes(reconstructed_payload[:4]))
    if secret_len > len(reconstructed_payload) - 4:
        raise SecretSharingError(
            f"Corrupted secret length: header states {secret_len} bytes"
        )

    return bytes(reconstructed_payload[4 : 4 + secret_len])
