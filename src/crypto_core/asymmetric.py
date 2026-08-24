"""Asymmetric cryptography: ECDSA on curve SECP256R1 (P-256) with SHA-256 (C1).

All primitive calls to ``cryptography.hazmat`` are contained within ``crypto_core``
per CONVENTIONS.md §2 rule 1.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from crypto_core.exceptions import InvalidSignatureError, KeyFormatError


def generate_ec_keypair() -> (
    tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]
):
    """Generate an ECDSA private and public keypair on curve SECP256R1 (P-256).

    Returns:
        A tuple of ``(private_key, public_key)``.

    Security property:
        Key generation utilizes high-entropy system randomness.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign a message using ECDSA with SHA-256.

    Args:
        private_key: The elliptic curve private key.
        message: The byte string to sign.

    Returns:
        The DER-encoded signature bytes.

    Security property:
        Digital signature provides authenticity, non-repudiation, and integrity.
    """
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(
    public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes
) -> bool:
    """Verify an ECDSA SHA-256 signature against a message.

    Args:
        public_key: The signer's elliptic curve public key.
        message: The original unsigned message bytes.
        signature: The DER-encoded signature bytes.

    Returns:
        True if the signature is valid.

    Raises:
        InvalidSignatureError: If the signature is invalid or tampered with.

    Security property:
        Fails closed on invalid or tampered signature (CONVENTIONS.md §2 rule 6).
    """
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature as exc:
        raise InvalidSignatureError("ECDSA signature verification failed") from exc


def private_key_to_pem(
    private_key: ec.EllipticCurvePrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialize an EC private key to PKCS8 PEM bytes.

    Args:
        private_key: The private key object.
        password: Optional password bytes for encryption.

    Returns:
        PEM-formatted bytes.
    """
    if password is not None:
        encryption_algorithm: serialization.KeySerializationEncryption = (
            serialization.BestAvailableEncryption(password)
        )
    else:
        encryption_algorithm = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )


def private_key_from_pem(
    pem_bytes: bytes,
    password: bytes | None = None,
) -> ec.EllipticCurvePrivateKey:
    """Deserialize an EC private key from PKCS8 PEM bytes.

    Args:
        pem_bytes: The PEM-encoded private key bytes.
        password: Optional password if the key is encrypted.

    Returns:
        The deserialized private key.

    Raises:
        KeyFormatError: If the PEM bytes are invalid or cannot be parsed.
    """
    try:
        key = serialization.load_pem_private_key(pem_bytes, password=password)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise KeyFormatError(f"Expected EC private key, got {type(key).__name__}")
        return key
    except Exception as exc:
        raise KeyFormatError(f"Failed to load EC private key from PEM: {exc}") from exc


def public_key_to_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize an EC public key to SubjectPublicKeyInfo PEM bytes.

    Args:
        public_key: The public key object.

    Returns:
        PEM-formatted bytes.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(pem_bytes: bytes) -> ec.EllipticCurvePublicKey:
    """Deserialize an EC public key from SubjectPublicKeyInfo PEM bytes.

    Args:
        pem_bytes: The PEM-encoded public key bytes.

    Returns:
        The deserialized public key.

    Raises:
        KeyFormatError: If the PEM bytes are invalid or cannot be parsed.
    """
    try:
        key = serialization.load_pem_public_key(pem_bytes)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise KeyFormatError(f"Expected EC public key, got {type(key).__name__}")
        return key
    except Exception as exc:
        raise KeyFormatError(f"Failed to load EC public key from PEM: {exc}") from exc
