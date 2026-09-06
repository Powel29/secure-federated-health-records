"""Unit tests for the Hospital Node Ingest endpoint (P4-1, P3-14).

Verifies:
- POST /records/ingest encrypts plaintext under fresh DEK, attaches owner leaf,
  indexes search terms, and marks state as GRANTED.
- Refuses ingest with missing emergency key when search terms are provided.
"""

from __future__ import annotations

import base64

import pytest
from contracts.enums import LifecycleState


class TestHospitalIngestEndpoint:
    """Test suite for POST /records/ingest."""

    def test_ingest_record_success(self, test_setup):
        """Valid ingest produces an encrypted record, wrapping, and coded index."""
        client = test_setup["client"]
        attrs = test_setup["attrs"]
        em_key = test_setup["em_key"]

        plaintext = b'{"notes": "Blood pressure elevated", "systolic": 140}'
        plaintext_b64 = base64.b64encode(plaintext).decode("ascii")
        em_key_b64 = base64.b64encode(em_key).decode("ascii")

        ingest_keyring = dict(attrs["b64_keyring"])
        ingest_keyring["authority-net:owner:patient-002"] = base64.b64encode(
            b"k_owner_patient002_32bytes_samp!"
        ).decode("ascii")

        response = client.post(
            "/records/ingest",
            json={
                "plaintext_b64": plaintext_b64,
                "patient_id": "patient-002",
                "owner_authority_id": "authority-net",
                "clinical_policy": attrs["clinical_policy"].model_dump(
                    mode="json"
                ),
                "attribute_keyring": ingest_keyring,
                "search_terms": ["hypertension", "systolic"],
                "emergency_key_b64": em_key_b64,
                "record_id": "rec-002",
            },
        )

        assert response.status_code == 201
        data = response.json()
        assert data["record_id"] == "rec-002"
        assert data["lifecycle_state"] == LifecycleState.GRANTED.value
        assert data["search_terms_indexed"] == 2

        # Verify record is now retrievable in repository
        repo = test_setup["repo"]
        rec = repo.get_record("rec-002")
        assert rec is not None
        assert rec.patient_id == "patient-002"
        assert rec.ciphertext != plaintext

    def test_ingest_missing_emergency_key_for_search_terms_fails(
        self, test_setup
    ):
        """Providing search terms without an emergency key fails (400)."""
        client = test_setup["client"]
        attrs = test_setup["attrs"]

        plaintext = b'{"notes": "Test"}'
        plaintext_b64 = base64.b64encode(plaintext).decode("ascii")

        response = client.post(
            "/records/ingest",
            json={
                "plaintext_b64": plaintext_b64,
                "patient_id": "patient-003",
                "owner_authority_id": "authority-net",
                "clinical_policy": attrs["clinical_policy"].model_dump(
                    mode="json"
                ),
                "attribute_keyring": attrs["b64_keyring"],
                "search_terms": ["cardiac"],
                # Missing emergency_key_b64
            },
        )

        assert response.status_code == 400
        assert "Ingest failed" in response.json()["detail"]
