"""Unambiguous byte encoding for signed and hashed field lists (review D9, ADR-0077).

Every signature and chain hash in the project covers a list of fields. Joining
them with a separator byte is ambiguous when a field can contain that byte, and
two message types with the same field shapes produce interchangeable bytes.
:func:`encode_fields` fixes both: a domain tag naming the message type comes
first, and every part is prefixed by its 4-byte big-endian length, so the byte
string decodes to exactly one ``(domain, fields)`` list.

This is an encoding, not a cryptographic construction: it only decides which
bytes the existing ECDSA signatures, SHA-256 hashes and AES-GCM AAD cover.
"""

from __future__ import annotations

from collections.abc import Sequence

_LENGTH_BYTES = 4


def encode_fields(domain: str, fields: Sequence[bytes]) -> bytes:
    """Length-prefix ``domain`` and then each field, in order.

    Args:
        domain: The message type, e.g. ``"ehr/transition-event/v1"``. Distinct
            per message type so a signature over one type never verifies as
            another.
        fields: The field values as bytes, in a fixed order per domain.

    Raises:
        TypeError: A field is not ``bytes`` (an implicit ``str`` would make the
            encoding depend on the caller's choice of codec).
        ValueError: A part is too long for the 4-byte length prefix.
    """
    out = bytearray()
    for part in (domain.encode("utf-8"), *fields):
        if not isinstance(part, bytes):
            raise TypeError(f"encode_fields takes bytes, got {type(part).__name__}")
        if len(part) >= 1 << (8 * _LENGTH_BYTES):
            raise ValueError("field too long to encode")
        out += len(part).to_bytes(_LENGTH_BYTES, "big")
        out += part
    return bytes(out)
