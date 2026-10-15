"""Signed and wrapped bytes are unambiguous (review D9 and F29, ADR-0077).

Each test changes a field in a way the old ``0x1f``-joined encoding could not
see, or reuses bytes across types or generations, and asserts verification or
unwrapping now fails closed.
"""

from __future__ import annotations

import pytest
from consent.service import create_consent_request, verify_consent_request
from crypto_core import InvalidSignatureError, encode_fields, generate_ec_keypair
from crypto_core.symmetric import generate_key
from records.exceptions import UnwrappingError
from records.service import unwrap_dek, wrap_dek


def test_encoding_keeps_field_boundaries():
    """The old join made ``["a\\x1fb", "c"]`` and ``["a", "b\\x1fc"]`` equal."""
    assert encode_fields("d", [b"a\x1fb", b"c"]) != encode_fields(
        "d", [b"a", b"b\x1fc"]
    )
    assert encode_fields("d", [b"ab"]) != encode_fields("d", [b"a", b"b"])
    assert encode_fields("d", [b""]) != encode_fields("d", [])


def test_encoding_separates_domains():
    """The same fields under two message types never give the same bytes."""
    fields = [b"rec-1", b"pat-1"]
    assert encode_fields("ehr/transition-event/v1", fields) != encode_fields(
        "ehr/emergency-assertion/v1", fields
    )


def test_encoding_refuses_text():
    with pytest.raises(TypeError):
        encode_fields("d", ["not bytes"])  # type: ignore[list-item]


def test_consent_scope_cannot_be_resplit():
    """A request signed for one record id containing 0x1f cannot be read as
    two records: under the old encoding both scopes signed the same bytes."""
    priv, pub = generate_ec_keypair()
    request = create_consent_request(
        patient_id="pat-1",
        requester_id="dr-1",
        scope=("rec-1\x1frec-2",),
        purpose="follow-up",
        requester_signing_key=priv,
    )
    verify_consent_request(request, pub)  # positive control

    widened = request.model_copy(update={"scope": ("rec-1", "rec-2")})
    with pytest.raises(InvalidSignatureError):
        verify_consent_request(widened, pub)


def _wrapping(generation: int = 1):
    key = generate_key()
    wrapping = wrap_dek(
        dek=generate_key(),
        record_id="rec-1",
        wrapping_key=key,
        wrapped_for="pol-new",
        generation=generation,
    )
    return wrapping, key


def test_old_generation_wrapping_does_not_unwrap_as_current():
    """F29: a stored wrapping relabelled as another generation (rollback) fails."""
    wrapping, key = _wrapping(generation=1)
    assert unwrap_dek(wrapping, key)  # positive control

    with pytest.raises(UnwrappingError):
        unwrap_dek(wrapping.model_copy(update={"generation": 2}), key)


def test_wrapping_does_not_unwrap_for_another_policy():
    wrapping, key = _wrapping()
    with pytest.raises(UnwrappingError):
        unwrap_dek(wrapping.model_copy(update={"wrapped_for": "pol-old"}), key)
