"""Unit tests for request envelope creation and validation (P3-11).

Covers:
- Creation round-trip: create → verify.
- Recipient binding.
- Anti-replay integration with consumed store.
"""

from __future__ import annotations

import pytest
from breakglass import (
    ConsumedRequestIds,
    EnvelopeRecipientMismatchError,
    ReplayedRequestError,
    create_request_envelope,
    verify_request_envelope,
)
from crypto_core import generate_ec_keypair

# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------


class TestCreateRequestEnvelope:
    """Creating an envelope produces a well-formed, signed object."""

    def test_round_trip(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="request_share",
            body=b"payload-bytes",
            signing_key=priv,
        )
        assert envelope.caller_id == "facility-a"
        assert envelope.recipient_id == "audit-service"
        assert envelope.operation == "request_share"
        assert envelope.body == b"payload-bytes"

    def test_unique_request_ids(self):
        priv, _ = generate_ec_keypair()
        e1 = create_request_envelope(
            caller_id="f-a",
            recipient_id="audit",
            operation="op",
            body=b"x",
            signing_key=priv,
        )
        e2 = create_request_envelope(
            caller_id="f-a",
            recipient_id="audit",
            operation="op",
            body=b"x",
            signing_key=priv,
        )
        assert e1.request_id != e2.request_id


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


class TestVerifyRequestEnvelope:
    """Envelope verification: signature, recipient, and replay."""

    def test_valid_envelope(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="request_share",
            body=b"payload",
            signing_key=priv,
        )
        # Should not raise
        verify_request_envelope(envelope, pub, "audit-service")

    def test_wrong_recipient_rejected(self):
        priv, pub = generate_ec_keypair()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="request_share",
            body=b"payload",
            signing_key=priv,
        )
        with pytest.raises(EnvelopeRecipientMismatchError):
            verify_request_envelope(envelope, pub, "wrong-service")

    def test_with_consumed_store(self):
        priv, pub = generate_ec_keypair()
        store = ConsumedRequestIds()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        verify_request_envelope(envelope, pub, "audit-service", consumed_store=store)
        assert store.has_seen(envelope.request_id)

    def test_replay_rejected(self):
        priv, pub = generate_ec_keypair()
        store = ConsumedRequestIds()
        envelope = create_request_envelope(
            caller_id="facility-a",
            recipient_id="audit-service",
            operation="op",
            body=b"data",
            signing_key=priv,
        )
        verify_request_envelope(envelope, pub, "audit-service", consumed_store=store)
        with pytest.raises(ReplayedRequestError):
            verify_request_envelope(
                envelope, pub, "audit-service", consumed_store=store
            )
