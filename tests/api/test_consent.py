"""Unit tests for the Hospital Node Consent endpoints (P4-1).

Verifies:
- POST /consent/requests creates a valid, signed ConsentRequest.
- POST /consent/grants validates and registers a patient-signed ConsentGrant.
- POST /consent/grants rejects forged or tampered signatures with HTTP 400.
- POST /consent/grants/revoke produces a signed REVOKED grant.
"""

from __future__ import annotations

from consent.service import create_consent_grant, create_consent_request
from contracts.enums import ConsentStatus
from crypto_core import (
    generate_ec_keypair,
    private_key_to_pem,
    public_key_to_pem,
)


class TestHospitalConsentEndpoints:
    """Test suite for /consent routes."""

    def test_create_consent_request(self, test_setup):
        """Clinician creates a signed ConsentRequest."""
        client = test_setup["client"]
        pki = test_setup["pki"]

        alice_priv_pem = private_key_to_pem(pki["alice_priv"]).decode("ascii")

        response = client.post(
            "/consent/requests",
            json={
                "patient_id": "patient-001",
                "requester_id": "dr-alice",
                "scope": ["rec-001"],
                "purpose": "Consultation",
                "ttl_days": 7,
                "requester_signing_key_pem": alice_priv_pem,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "created"
        assert data["request"]["patient_id"] == "patient-001"
        assert data["request"]["requester_id"] == "dr-alice"
        assert data["request"]["scope"] == ["rec-001"]

    def test_submit_valid_consent_grant(self, test_setup):
        """Patient submits a valid signed grant."""
        client = test_setup["client"]
        pki = test_setup["pki"]

        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Consultation",
            requester_signing_key=pki["alice_priv"],
        )
        grant = create_consent_grant(
            request=req,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
        )
        pat_pub_pem = public_key_to_pem(pki["pat_pub"]).decode("ascii")

        response = client.post(
            "/consent/grants",
            json={
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert data["grant"]["status"] == ConsentStatus.GRANTED.value

    def test_submit_forged_consent_grant_rejected(self, test_setup):
        """A grant with mismatched patient public key is rejected (400)."""
        client = test_setup["client"]
        pki = test_setup["pki"]

        # Signed with a foreign key
        foreign_priv, _ = generate_ec_keypair()
        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Consultation",
            requester_signing_key=pki["alice_priv"],
        )
        grant = create_consent_grant(
            request=req,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=foreign_priv,  # forged/wrong signer
        )
        pat_pub_pem = public_key_to_pem(pki["pat_pub"]).decode("ascii")

        response = client.post(
            "/consent/grants",
            json={
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
            },
        )

        assert response.status_code == 400
        assert "signature verification failed" in response.json()["detail"]

    def test_revoke_consent_grant(self, test_setup):
        """Patient successfully revokes a prior grant."""
        client = test_setup["client"]
        pki = test_setup["pki"]

        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Consultation",
            requester_signing_key=pki["alice_priv"],
        )
        prior_grant = create_consent_grant(
            request=req,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
        )
        pat_priv_pem = private_key_to_pem(pki["pat_priv"]).decode("ascii")

        response = client.post(
            "/consent/grants/revoke",
            json={
                "prior_grant": prior_grant.model_dump(mode="json"),
                "patient_signing_key_pem": pat_priv_pem,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "revoked"
        assert data["grant"]["status"] == ConsentStatus.REVOKED.value
