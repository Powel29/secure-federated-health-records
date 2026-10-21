"""Threshold shares travel sealed to their recipient (review D6 step 2, ADR-0079).

A share is only ever readable by the service it is addressed to: the audit
service (share 3 and 4 deposits), the patient's home authority (share 2
deposits), the custodian (share 1 deposits) or the facility whose gate
combines them (break-glass). Nothing in between -- including the custodian
forwarding the audit service's shares 3 and 4 or the home authority's share
2 -- sees share bytes.

Two pieces, both built from primitives the project already uses:

1. **Share-key statement.** Each of those services holds an ElGamal key pair
   (:func:`pre.generate_keypair`) and publishes the public key in a statement
   signed with its root-certified service key (ADR-0066), over
   ``encode_fields("ehr/share-sealing-key/v1", [service_id, kind, key])``.
   A sender trusts the key only after :func:`verify_key_statement` has checked
   the certificate against its own configured root, that the certificate
   names that service id and kind, and the signature.
2. **Sealed share.** The same KEM the gate's DEK delivery uses
   (:func:`pre.encapsulate_key`) gives a fresh AES-256-GCM key; the share is
   encrypted under it with AAD
   ``encode_fields("ehr/sealed-share/v1", [record_id, x, recipient_id])``, so
   a sealed share cannot be redirected to another service, moved to another
   record, or have its index changed.

The ElGamal group is the project's 256-bit safe-prime group (ADR-0018), a
demonstration parameter, not a production one; ADR-0079 says so.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field

from crypto_core import (
    CryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    certificate_from_pem,
    certificate_public_key,
    encode_fields,
    sign,
    verify,
)
from crypto_core.types import ECPrivateKey
from cryptography.x509 import Certificate
from identity import validate_service_certificate
from pre import decapsulate_key, encapsulate_key, generate_keypair
from pre.exceptions import PREError
from pydantic import BaseModel

from breakglass.emergency_key import Share
from breakglass.exceptions import SealedShareError

_STATEMENT_DOMAIN = "ehr/share-sealing-key/v1"
_SHARE_DOMAIN = "ehr/sealed-share/v1"


class ShareKeyStatement(BaseModel):
    """A service's share-sealing public key, signed by its service identity."""

    service_id: str
    kind: str
    public_key: int
    certificate_pem: str
    signature_b64: str


class SealedShare(BaseModel):
    """One share encrypted to one recipient; ``x`` is public, the value is not."""

    x: int
    c1: int
    c2: int
    nonce_b64: str
    ciphertext_b64: str


@dataclass(frozen=True)
class ShareSealingKey:
    """This service's ElGamal key pair for receiving shares."""

    private_key: int = field(repr=False)
    public_key: int

    @classmethod
    def generate(cls) -> ShareSealingKey:
        private_key, public_key = generate_keypair()
        return cls(private_key=private_key, public_key=public_key)


@dataclass(frozen=True)
class ShareRecipient:
    """A verified recipient: who it is and the key shares are sealed to."""

    service_id: str
    public_key: int


def _statement_payload(service_id: str, kind: str, public_key: int) -> bytes:
    return encode_fields(
        _STATEMENT_DOMAIN,
        [service_id.encode("utf-8"), kind.encode("utf-8"), str(public_key).encode()],
    )


def _share_aad(record_id: str, x: int, recipient_id: str) -> bytes:
    return encode_fields(
        _SHARE_DOMAIN,
        [record_id.encode("utf-8"), str(x).encode(), recipient_id.encode("utf-8")],
    )


def make_key_statement(
    key: ShareSealingKey,
    *,
    service_id: str,
    kind: str,
    signing_key: ECPrivateKey,
    certificate_pem: str,
) -> ShareKeyStatement:
    """Sign this service's share-sealing public key with its service key."""
    signature = sign(signing_key, _statement_payload(service_id, kind, key.public_key))
    return ShareKeyStatement(
        service_id=service_id,
        kind=kind,
        public_key=key.public_key,
        certificate_pem=certificate_pem,
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


def verify_key_statement(
    statement: ShareKeyStatement, *, trusted_root: Certificate, kind: str
) -> ShareRecipient:
    """Trust a share-sealing key only from a root-issued service of ``kind``.

    Args:
        statement: What the recipient published.
        trusted_root: The federation root from the sender's own configuration.
        kind: The service kind the sender means to reach (``audit``, ``authority``,
            ``custodian`` or ``facility``).

    Raises:
        SealedShareError: The certificate does not chain to ``trusted_root``,
            is not a service certificate, names another service or kind, or
            the signature does not verify.
    """
    try:
        certificate = certificate_from_pem(statement.certificate_pem.encode("ascii"))
        name = validate_service_certificate(certificate, trusted_root=trusted_root)
        if (name.service_id, name.kind) != (statement.service_id, statement.kind):
            raise SealedShareError(
                "statement names another service than its certificate"
            )
        if name.kind != kind:
            raise SealedShareError(f"share key belongs to a {name.kind}, not a {kind}")
        verify(
            certificate_public_key(certificate),
            _statement_payload(
                statement.service_id, statement.kind, statement.public_key
            ),
            base64.b64decode(statement.signature_b64, validate=True),
        )
    except (CryptoError, binascii.Error, UnicodeError) as exc:
        if isinstance(exc, SealedShareError):
            raise
        raise SealedShareError(f"share-key statement refused: {exc}") from exc
    return ShareRecipient(
        service_id=statement.service_id, public_key=statement.public_key
    )


def seal_share(
    share: Share, *, record_id: str, recipient: ShareRecipient
) -> SealedShare:
    """Encrypt ``share`` so only ``recipient`` can open it, for this record.

    Raises:
        SealedShareError: The recipient's key is not a valid group element.
    """
    x, value = share
    try:
        (c1, c2), delivery_key = encapsulate_key(recipient.public_key)
    except PREError as exc:
        raise SealedShareError(f"recipient share key unusable: {exc}") from exc
    ciphertext, nonce = aes_gcm_encrypt(
        key=delivery_key,
        plaintext=value,
        aad=_share_aad(record_id, x, recipient.service_id),
    )
    return SealedShare(
        x=x,
        c1=c1,
        c2=c2,
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
    )


def open_sealed_share(
    sealed: SealedShare, *, record_id: str, service_id: str, key: ShareSealingKey
) -> Share:
    """Open a share sealed to this service for ``record_id``.

    Raises:
        SealedShareError: It was sealed to another key or service, for another
            record or index, or it was tampered with.
    """
    try:
        delivery_key = decapsulate_key(key.private_key, sealed.c1, sealed.c2)
        value = aes_gcm_decrypt(
            key=delivery_key,
            nonce=base64.b64decode(sealed.nonce_b64, validate=True),
            ciphertext=base64.b64decode(sealed.ciphertext_b64, validate=True),
            aad=_share_aad(record_id, sealed.x, service_id),
        )
    except (CryptoError, PREError, binascii.Error, ValueError) as exc:
        raise SealedShareError(
            f"share x={sealed.x} for {record_id!r} does not open here"
        ) from exc
    return sealed.x, value
