"""Unit tests for the Hospital Node Search & Discovery endpoints (P4-1, C12, C13).

Verifies:
- Federated discovery (GET /patients/{patient_id}/records) returns patient's records.
- Equality search on encrypted index with coded token (POST /search/records).
- Emergency-only search using active emergency session (P3-8).
- Refusal of emergency search when session is expired (403).
"""

from __future__ import annotations

import base64

from search.service import derive_search_token


class TestHospitalSearchEndpoints:
    """Test suite for search and discovery endpoints."""

    def test_federated_discovery(self, test_setup):
        """GET /patients/{patient_id}/records locates patient's records."""
        client = test_setup["client"]

        response = client.get("/patients/patient-001/records")
        assert response.status_code == 200
        data = response.json()
        assert data["patient_id"] == "patient-001"
        assert "rec-001" in data["record_ids"]
        assert data["record_count"] >= 1

    def test_search_coded_index(self, test_setup):
        """POST /search/records matches record via derived search token."""
        client = test_setup["client"]
        em_key = test_setup["em_key"]

        # Derive search token for "cardiac"
        coded_token = derive_search_token(em_key, "cardiac")
        coded_b64 = base64.b64encode(coded_token).decode("ascii")

        response = client.post(
            "/search/records",
            json={"coded_term_b64": coded_b64},
        )

        assert response.status_code == 200
        data = response.json()
        assert "rec-001" in data["record_ids"]
        assert data["record_count"] >= 1

    def test_emergency_search_during_active_session(self, test_setup):
        """Emergency search succeeds when an emergency session is active."""
        client = test_setup["client"]
        expiry_manager = test_setup["expiry_manager"]

        # Register active emergency session in expiry_manager
        expiry_manager.register_session(
            record_id="rec-001",
            actor_id="dr-alice",
            correlation_id="corr-search-001",
            emergency_key=test_setup["em_key"],
            baseline_wrapping_key=b"k_base_32bytes_sample_key_001!",
            baseline_wrapping=test_setup["wrapping"],
            emergency_wrapping=test_setup["em_wrapping"],
            current_record=test_setup["record"],
            duration_seconds=300.0,
        )

        response = client.post(
            "/records/rec-001/emergency-search",
            json={"search_term": "cardiac"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "rec-001" in data["record_ids"]

    def test_emergency_search_refused_after_expiry(self, test_setup):
        """Emergency search fails closed with 403 once session expires (P3-8)."""
        client = test_setup["client"]
        expiry_manager = test_setup["expiry_manager"]

        # Register session with 0-second duration so it is immediately expired
        expiry_manager.register_session(
            record_id="rec-001",
            actor_id="dr-alice",
            correlation_id="corr-search-002",
            emergency_key=test_setup["em_key"],
            baseline_wrapping_key=b"k_base_32bytes_sample_key_001!",
            baseline_wrapping=test_setup["wrapping"],
            emergency_wrapping=test_setup["em_wrapping"],
            current_record=test_setup["record"],
            duration_seconds=-1.0,
        )

        response = client.post(
            "/records/rec-001/emergency-search",
            json={"search_term": "cardiac"},
        )

        assert response.status_code == 403
        assert "Emergency search unavailable" in response.json()["detail"]
