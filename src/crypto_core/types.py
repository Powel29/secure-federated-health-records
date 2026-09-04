"""Type aliases for cryptographic key objects.

All direct ``cryptography.hazmat`` imports remain contained within
``crypto_core``. Other modules should use these aliases instead.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

ECPrivateKey = EllipticCurvePrivateKey
ECPublicKey = EllipticCurvePublicKey

__all__ = ["ECPrivateKey", "ECPublicKey"]
