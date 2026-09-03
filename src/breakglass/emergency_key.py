"""Emergency key generation and 2-of-3 threshold split (P3-5, ARCHITECTURE.md §8).

The emergency key is the 256-bit secret that authorizes break-glass DEK
recovery. It is never held whole by any single party: it is split three ways
(one share each to, e.g., the requesting facility, the patient's home
authority, and the federation audit service) with a 2-of-3 reconstruction
threshold, so no single custodian -- including the audit service -- can open
a record unilaterally (see ``tests/security/test_phase3_breakglass_security.py``).
"""

from __future__ import annotations

from crypto_core.symmetric import generate_key
from shamir.split import split_secret

EMERGENCY_KEY_BYTES = 32  # 256-bit emergency key
THRESHOLD = 2  # k: shares required to reconstruct
TOTAL_SHARES = 3  # n: shares issued

# Matches shamir.split.split_secret's return shape: (x, share_bytes) per share.
Share = tuple[int, bytes]


def generate_emergency_key() -> bytes:
    """Generate a fresh 256-bit emergency key.

    Returns:
        32 random bytes from the system CSPRNG.

    Security property:
        Entropy is drawn via ``crypto_core.symmetric.generate_key``
        (CONVENTIONS.md §2 rule 2); never derived or reused.
    """
    return generate_key(EMERGENCY_KEY_BYTES)


def split_emergency_key(key: bytes) -> list[Share]:
    """Split an emergency key into a 2-of-3 threshold Shamir sharing.

    Args:
        key: The 256-bit emergency key to split.

    Returns:
        A list of ``TOTAL_SHARES`` shares; any ``THRESHOLD`` of them
        reconstruct ``key`` via :func:`shamir.split.combine_shares`.

    Security property:
        Information-theoretic: any ``THRESHOLD - 1`` shares reveal nothing
        about ``key`` (shamir's guarantee, CONVENTIONS.md §2).
    """
    return split_secret(secret=key, k=THRESHOLD, n=TOTAL_SHARES)
