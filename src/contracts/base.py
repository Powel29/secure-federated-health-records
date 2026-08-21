"""Shared model infrastructure for every frozen contract.

Nothing here computes cryptography. Contracts are typed value objects that carry
opaque crypto material (`bytes`) across module and process boundaries; the
signing, verification, and encryption that produce those bytes live in the owning
modules and go through `crypto_core` (CONVENTIONS.md §2 rule 1). This module
exists so all eleven schemas share one base configuration and one wire encoding.
"""

from __future__ import annotations

import base64
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, PlainSerializer


def _decode_b64(value: object) -> bytes:
    """Accept raw bytes or a base64 string; reject anything else, fail closed.

    Args:
        value: `bytes`/`bytearray` (passed through) or a base64-encoded `str`.

    Returns:
        The decoded bytes.

    Raises:
        TypeError: value is neither bytes nor str.
        ValueError: value is a str that is not valid base64.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        # validate=True rejects non-alphabet characters rather than silently
        # dropping them -- a malformed field must fail, not decode partially.
        return base64.b64decode(value, validate=True)
    raise TypeError(f"expected bytes or base64 str, got {type(value).__name__}")


def _encode_b64(value: bytes) -> str:
    """Serialize bytes as a base64 string for JSON transport."""
    return base64.b64encode(value).decode("ascii")


# A `bytes` field that round-trips through JSON as base64. In Python mode
# (`model_dump()`) it stays `bytes`; in JSON mode (`model_dump_json()`) it is
# base64. Binary crypto material (ciphertext, signatures, nonces, digests) must
# cross the wire without corruption, and raw bytes are not JSON-safe.
B64Bytes = Annotated[
    bytes,
    BeforeValidator(_decode_b64),
    PlainSerializer(_encode_b64, return_type=str, when_used="json"),
]

# A non-empty domain identifier (patient_id, record_id, facility_id, ...). These
# are opaque strings assigned by the system, not secrets.
Identifier = Annotated[str, Field(min_length=1)]

SHA256_DIGEST_BYTES = 32  # audit chain hashes (ARCHITECTURE.md §2 C10)
GCM_NONCE_BYTES = 12  # 96-bit AES-256-GCM nonce produced by crypto_core (T08)
MIN_ANTIREPLAY_NONCE_BYTES = 16  # 128-bit random nonce for assertions/envelopes


class ContractModel(BaseModel):
    """Base for every frozen contract schema.

    Configuration choices are security decisions, not style:

    - ``frozen=True`` -- a contract is an immutable value object. A structure
      that has been signed must not mutate after signing; freezing makes that a
      type-level guarantee and makes instances hashable.
    - ``extra="forbid"`` -- an unknown field is rejected, not ignored. Silently
      dropping fields off the wire is the opposite of fail-closed
      (CONVENTIONS.md §2 rule 6); a tampered or version-skewed message must raise.
    - ``validate_default=True`` -- defaults are validated like any other value.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        validate_default=True,
    )


class Attribute(ContractModel):
    """A single ``name:value`` attribute, e.g. ``role:physician``.

    The unit an authority certifies (see :class:`AttributeCredential`) and the
    unit a policy-tree leaf tests against (see :class:`PolicyTree`).
    """

    name: Identifier
    value: Identifier
