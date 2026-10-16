"""Unit tests for the Hospital Node Consent endpoints (P4-1).

Verifies:
- POST /consent/grants validates and registers a patient-signed ConsentGrant.
- POST /consent/grants rejects forged or tampered signatures with HTTP 400.
- A REVOKED grant, signed where the patient's key lives (the custodian), is
  submitted through the same route; no route takes a private key (review D6).
"""

from __future__ import annotations

from consent.service import (
    create_consent_grant,
    create_consent_request,
    revoke_consent_grant,
)
from contracts.enums import ConsentStatus
from crypto_core import generate_ec_keypair


class TestHospitalConsentEndpoints:
    """Test suite for /consent routes."""

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
        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/consent/grants",
            json={
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
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
        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/consent/grants",
            json={
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
            },
        )

        assert response.status_code == 400
        assert "signature verification failed" in response.json()["detail"]

    def test_revoked_grant_is_submitted_like_any_grant(self, test_setup):
        """The patient's signed REVOKED grant replaces the prior one."""
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
        revoked = revoke_consent_grant(
            prior_grant=prior_grant, patient_signing_key=pki["pat_priv"]
        )

        response = client.post(
            "/consent/grants",
            json={
                "grant": revoked.model_dump(mode="json"),
                "patient_certificate_pem": pki["pat_cert_pem"],
            },
        )

        assert response.status_code == 200
        assert response.json()["grant"]["status"] == ConsentStatus.REVOKED.value

    def test_routes_that_took_a_private_key_are_gone(self, test_setup):
        """Review D6: consent requests and revocations are signed by the
        custodian; the facility has no route that accepts the key."""
        client = test_setup["client"]
        for path in ("/consent/requests", "/consent/grants/revoke"):
            assert client.post(path, json={}).status_code in (404, 405)

    def test_stale_granted_copy_cannot_undo_a_revocation(self, test_setup):
        """Review F13: once the request is revoked, re-submitting the old
        GRANTED grant -- still validly signed by the patient -- is refused and
        the store keeps the revocation (a revocation is a new grant answering
        the same request)."""
        pki = test_setup["pki"]
        client = test_setup["client"]
        request = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Consultation",
            requester_signing_key=pki["alice_priv"],
        )
        prior = create_consent_grant(
            request=request,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
        )
        revoked = revoke_consent_grant(
            prior_grant=prior, patient_signing_key=pki["pat_priv"]
        )
        for grant in (prior, revoked):
            assert (
                client.post(
                    "/consent/grants",
                    json={
                        "grant": grant.model_dump(mode="json"),
                        "patient_certificate_pem": pki["pat_cert_pem"],
                    },
                ).status_code
                == 200
            )

        replay = client.post(
            "/consent/grants",
            json={
                "grant": prior.model_dump(mode="json"),
                "patient_certificate_pem": pki["pat_cert_pem"],
            },
        )

        assert replay.status_code == 409
        stored = test_setup["repo"].get_consent_grant(revoked.grant_id)
        assert stored.status is ConsentStatus.REVOKED
