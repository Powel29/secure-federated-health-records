"""Cross-cutting invariants that must hold for every frozen contract.

These are the properties the base configuration promises: all nine schemas are
importable by bare name, they are immutable, they reject unknown fields, and
their ``bytes`` fields survive a JSON round-trip as base64. Each is a fail-closed
guarantee the rest of the system relies on, so each has a negative case.
"""

from __future__ import annotations

import base64

import contracts
import pytest
from contracts import (
    AttributeCredential,
    AuditEntry,
    DEKWrapping,
    EmergencyAssertion,
    Facility,
    PolicyTree,
    Record,
    RequestEnvelope,
    TransitionEvent,
)
from pydantic import ValidationError

from .conftest import (
    attribute_credential_kwargs,
    audit_entry_kwargs,
    dek_wrapping_kwargs,
    emergency_assertion_kwargs,
    facility_kwargs,
    leaf_kwargs,
    record_kwargs,
    request_envelope_kwargs,
    transition_event_kwargs,
)

# (model, factory) for every one of the nine frozen schemas.
ALL_SCHEMAS = [
    (Record, record_kwargs),
    (DEKWrapping, dek_wrapping_kwargs),
    (PolicyTree, leaf_kwargs),
    (TransitionEvent, transition_event_kwargs),
    (AuditEntry, audit_entry_kwargs),
    (AttributeCredential, attribute_credential_kwargs),
    (Facility, facility_kwargs),
    (EmergencyAssertion, emergency_assertion_kwargs),
    (RequestEnvelope, request_envelope_kwargs),
]

EXPECTED_EXPORTS = {
    "Record",
    "DEKWrapping",
    "PolicyTree",
    "TransitionEvent",
    "AuditEntry",
    "AttributeCredential",
    "Facility",
    "EmergencyAssertion",
    "RequestEnvelope",
}


def test_all_nine_schemas_exported() -> None:
    """The freeze is nine schemas, each importable by bare name from contracts."""
    assert EXPECTED_EXPORTS.issubset(set(contracts.__all__))
    for name in EXPECTED_EXPORTS:
        assert hasattr(contracts, name)


@pytest.mark.parametrize("model, factory", ALL_SCHEMAS)
def test_valid_instance_constructs(model, factory) -> None:
    """Every schema accepts its known-good factory input."""
    assert model(**factory())


@pytest.mark.parametrize("model, factory", ALL_SCHEMAS)
def test_frozen_is_immutable(model, factory) -> None:
    """A signed value object must not mutate after construction (frozen=True)."""
    instance = model(**factory())
    field = next(iter(model.model_fields))
    with pytest.raises(ValidationError):
        setattr(instance, field, getattr(instance, field))


@pytest.mark.parametrize("model, factory", ALL_SCHEMAS)
def test_extra_field_rejected(model, factory) -> None:
    """An unknown field fails closed rather than being silently dropped."""
    with pytest.raises(ValidationError):
        model(**factory(unexpected_field="tamper"))


@pytest.mark.parametrize("model, factory", ALL_SCHEMAS)
def test_json_round_trip_is_stable(model, factory) -> None:
    """Every schema survives dump -> load through JSON unchanged."""
    instance = model(**factory())
    assert model.model_validate_json(instance.model_dump_json()) == instance


def test_bytes_field_serializes_as_base64() -> None:
    """A bytes field is base64 in JSON and decodes back to the original bytes."""
    rec = Record(**record_kwargs())
    dumped = rec.model_dump(mode="json")
    assert isinstance(dumped["ciphertext"], str)
    assert base64.b64decode(dumped["ciphertext"], validate=True) == rec.ciphertext


def test_base64_string_accepted_for_bytes_field() -> None:
    """A bytes field also accepts an incoming base64 string (wire ingress)."""
    raw = b"ciphertext-bytes"
    rec = Record(**record_kwargs(ciphertext=base64.b64encode(raw).decode()))
    assert rec.ciphertext == raw


def test_malformed_base64_rejected() -> None:
    """A non-base64 string in a bytes field fails closed."""
    with pytest.raises(ValidationError):
        Record(**record_kwargs(ciphertext="not valid base64 !!!"))
