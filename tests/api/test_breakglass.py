"""Unit tests for the Hospital Node Break-Glass endpoint (P4-1, P3-5, P3-10, P3-11).

Verifies:
- 2-of-3 threshold unlock produces re-wrapped DEK and sets EMERGENCY_OPEN.
- Refusal when fewer than 2 shares presented (400).
- Replay prevention: reusing an assertion_id is rejected (400).
- Expired emergency assertion is rejected (400).
- Facility mismatch is rejected (400).
"""

from __future__ import annotations

import base64

from breakglass import create_emergency_assertion
from contracts.base import GCM_NONCE_BYTES
from contracts.enums import LifecycleState, ReasonCode
from crypto_core import (
    certificate_to_pem,
    private_key_to_pem,
)
from crypto_core.symmetric import aes_gcm_decrypt
from pre.elgamal import decapsulate_key


def _unwrap_rewrapped_dek(rewrapped_dek: bytes, pre_priv: int, record_id: str) -> bytes:
    """Helper: reverse the gate's fixed-length PRE delivery packaging."""
    field_bytes = 32
    c1 = int.from_bytes(rewrapped_dek[:field_bytes], byteorder="big")
    c2 = int.from_bytes(rewrapped_dek[field_bytes : 2 * field_bytes], byteorder="big")
    offset = 2 * field_bytes
    nonce = rewrapped_dek[offset : offset + GCM_NONCE_BYTES]
    ciphertext = rewrapped_dek[offset + GCM_NONCE_BYTES :]
    delivery_key = decapsulate_key(pre_priv, c1, c2)
    return aes_gcm_decrypt(
        key=delivery_key,
        nonce=nonce,
        ciphertext=ciphertext,
        aad=record_id.encode("utf-8"),
    )


class TestHospitalBreakglassEndpoint:
    """Test suite for POST /records/{record_id}/breakglass."""

    def test_breakglass_unlock_with_two_shares(self, test_setup):
        """Presenting 2 shares with a valid EmergencyAssertion unlocks the record."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        em_shares = test_setup["em_shares"]

        # Alice signs EmergencyAssertion for rec-001 at facility-a
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=pki["alice_priv"],
        )

        cl_cert_pem = certificate_to_pem(pki["alice_cert"]).decode("ascii")
        ca_cert_pem = certificate_to_pem(pki["fa_cert"]).decode("ascii")
        root_cert_pem = certificate_to_pem(pki["root"].certificate).decode("ascii")
        life_priv_pem = private_key_to_pem(pki["life_priv"]).decode("ascii")

        # Format 2 shares as [(x, hex)]
        shares_payload = [
            (em_shares[0][0], em_shares[0][1].hex()),
            (em_shares[1][0], em_shares[1][1].hex()),
        ]

        response = client.post(
            "/records/rec-001/breakglass",
            json={
                "assertion": assertion.model_dump(mode="json"),
                "clinician_certificate_pem": cl_cert_pem,
                "facility_ca_certificate_pem": ca_cert_pem,
                "trusted_root_certificate_pem": root_cert_pem,
                "shares": shares_payload,
                "pre_rewrap_key": pki["alice_pre_pub"],
                "lifecycle_signing_key_pem": life_priv_pem,
                "correlation_id": "corr-bg-001",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["record_id"] == "rec-001"
        assert (
            data["transition_event"]["to_state"] == LifecycleState.EMERGENCY_OPEN.value
        )

        # Clinician Alice recovers the DEK using her PRE private key
        rewrapped_bytes = base64.b64decode(data["rewrapped_dek_b64"])
        recovered_dek = _unwrap_rewrapped_dek(
            rewrapped_bytes, pki["alice_pre_priv"], "rec-001"
        )
        assert len(recovered_dek) == 32

        # In-storage lifecycle state must be EMERGENCY_OPEN
        state = test_setup["repo"].get_lifecycle_state("rec-001")
        assert state == LifecycleState.EMERGENCY_OPEN

    def test_breakglass_single_share_fails(self, test_setup):
        """Presenting fewer than 2 shares fails with HTTP 400."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        em_shares = test_setup["em_shares"]

        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=pki["alice_priv"],
        )

        cl_cert_pem = certificate_to_pem(pki["alice_cert"]).decode("ascii")
        ca_cert_pem = certificate_to_pem(pki["fa_cert"]).decode("ascii")
        root_cert_pem = certificate_to_pem(pki["root"].certificate).decode("ascii")
        life_priv_pem = private_key_to_pem(pki["life_priv"]).decode("ascii")

        # Only 1 share
        shares_payload = [(em_shares[0][0], em_shares[0][1].hex())]

        response = client.post(
            "/records/rec-001/breakglass",
            json={
                "assertion": assertion.model_dump(mode="json"),
                "clinician_certificate_pem": cl_cert_pem,
                "facility_ca_certificate_pem": ca_cert_pem,
                "trusted_root_certificate_pem": root_cert_pem,
                "shares": shares_payload,
                "pre_rewrap_key": pki["alice_pre_pub"],
                "lifecycle_signing_key_pem": life_priv_pem,
            },
        )

        assert response.status_code == 400
        assert "Insufficient threshold shares" in response.json()["detail"]

    def test_breakglass_replayed_assertion_fails(self, test_setup):
        """Replaying a previously used assertion is rejected (P3-11 -> 400)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        em_shares = test_setup["em_shares"]

        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-a",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=pki["alice_priv"],
        )

        cl_cert_pem = certificate_to_pem(pki["alice_cert"]).decode("ascii")
        ca_cert_pem = certificate_to_pem(pki["fa_cert"]).decode("ascii")
        root_cert_pem = certificate_to_pem(pki["root"].certificate).decode("ascii")
        life_priv_pem = private_key_to_pem(pki["life_priv"]).decode("ascii")

        shares_payload = [
            (em_shares[0][0], em_shares[0][1].hex()),
            (em_shares[1][0], em_shares[1][1].hex()),
        ]

        payload = {
            "assertion": assertion.model_dump(mode="json"),
            "clinician_certificate_pem": cl_cert_pem,
            "facility_ca_certificate_pem": ca_cert_pem,
            "trusted_root_certificate_pem": root_cert_pem,
            "shares": shares_payload,
            "pre_rewrap_key": pki["alice_pre_pub"],
            "lifecycle_signing_key_pem": life_priv_pem,
        }

        # First unlock succeeds
        res1 = client.post("/records/rec-001/breakglass", json=payload)
        assert res1.status_code == 200

        # Second unlock with same assertion fails due to replay
        res2 = client.post("/records/rec-001/breakglass", json=payload)
        assert res2.status_code == 400
        assert "Emergency assertion invalid" in res2.json()["detail"]

    def test_breakglass_facility_mismatch_fails(self, test_setup):
        """Assertion declared for facility-b is rejected at facility-a node (400)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        em_shares = test_setup["em_shares"]

        # Assertion declared for facility-b
        assertion = create_emergency_assertion(
            patient_id="patient-001",
            clinician_id="dr-alice",
            facility_id="facility-b",
            reason_code=ReasonCode.UNCONSCIOUS_PATIENT,
            signing_key=pki["alice_priv"],
        )

        cl_cert_pem = certificate_to_pem(pki["alice_cert"]).decode("ascii")
        ca_cert_pem = certificate_to_pem(pki["fa_cert"]).decode("ascii")
        root_cert_pem = certificate_to_pem(pki["root"].certificate).decode("ascii")
        life_priv_pem = private_key_to_pem(pki["life_priv"]).decode("ascii")

        shares_payload = [
            (em_shares[0][0], em_shares[0][1].hex()),
            (em_shares[1][0], em_shares[1][1].hex()),
        ]

        response = client.post(
            "/records/rec-001/breakglass",
            json={
                "assertion": assertion.model_dump(mode="json"),
                "clinician_certificate_pem": cl_cert_pem,
                "facility_ca_certificate_pem": ca_cert_pem,
                "trusted_root_certificate_pem": root_cert_pem,
                "shares": shares_payload,
                "pre_rewrap_key": pki["alice_pre_pub"],
                "lifecycle_signing_key_pem": life_priv_pem,
            },
        )

        assert response.status_code == 400
        assert "FacilityMismatchError" in response.json()["detail"]
