"""Unit tests for the Hospital Node Consent endpoints (P4-1, ADR-0073).

Verifies:
- POST /consent/requests registers a ConsentRequest its clinician signed,
  verified against the clinician's certificate; no private key is accepted.
- POST /consent/grants validates and registers a patient-signed ConsentGrant.
- POST /consent/grants rejects forged or tampered signatures with HTTP 400.
- A revocation is the patient's signed REVOKED grant, submitted the same way;
  once revoked, the earlier GRANTED copy cannot be submitted again.
"""

from __future__ import annotations

import datetime

from consent.service import (
    create_consent_grant,
    create_consent_request,
    revoke_consent_grant,
)
from contracts.enums import ConsentStatus
from crypto_core import certificate_to_pem, generate_ec_keypair, private_key_to_pem


def _signed_request(pki, *, signing_key=None, ttl_days=7):
    return create_consent_request(
        patient_id="patient-001",
        requester_id="dr-alice",
        scope=("rec-001",),
        purpose="Consultation",
        requester_signing_key=signing_key or pki["alice_priv"],
        ttl=datetime.timedelta(days=ttl_days),
    )


def _alice_cert(pki) -> str:
    return certificate_to_pem(pki["alice_cert"]).decode("ascii")


def _grant(pki, status=ConsentStatus.GRANTED):
    return create_consent_grant(
        request=_signed_request(pki),
        status=status,
        grantee_id="dr-alice",
        patient_signing_key=pki["pat_priv"],
    )


class TestHospitalConsentEndpoints:
    """Test suite for /consent routes."""

    def test_register_signed_consent_request(self, test_setup):
        """A clinician-signed ConsentRequest is verified and registered."""
        pki = test_setup["pki"]
        req = _signed_request(pki, ttl_days=3)

        response = test_setup["client"].post(
            "/consent/requests",
            json={
                "request": req.model_dump(mode="json"),
                "requester_certificate_pem": _alice_cert(pki),
            },
        )

        assert response.status_code == 200, response.text
        data = response.json()
        assert data["status"] == "created"
        assert data["request"]["requester_id"] == "dr-alice"
        assert data["request"]["scope"] == ["rec-001"]
        assert test_setup["repo"].get_consent_request(req.request_id) == req

    def test_request_with_a_private_key_is_refused(self, test_setup):
        """Review F13/ADR-0073: the facility never takes a clinician's key."""
        pki = test_setup["pki"]
        response = test_setup["client"].post(
            "/consent/requests",
            json={
                "request": _signed_request(pki).model_dump(mode="json"),
                "requester_certificate_pem": _alice_cert(pki),
                "requester_signing_key_pem": private_key_to_pem(
                    pki["alice_priv"]
                ).decode("ascii"),
            },
        )
        assert response.status_code == 422

    def test_request_not_signed_by_its_requester_is_refused(self, test_setup):
        """Alice's certificate with someone else's signature registers nothing."""
        pki = test_setup["pki"]
        foreign, _ = generate_ec_keypair()
        req = _signed_request(pki, signing_key=foreign)
        response = test_setup["client"].post(
            "/consent/requests",
            json={
                "request": req.model_dump(mode="json"),
                "requester_certificate_pem": _alice_cert(pki),
            },
        )
        assert response.status_code == 403
        assert test_setup["repo"].get_consent_request(req.request_id) is None

    def test_request_under_another_clinicians_certificate_is_refused(self, test_setup):
        """The certificate must be the requester's own (Bob's names dr-bob)."""
        pki = test_setup["pki"]
        req = _signed_request(pki, signing_key=pki["bob_priv"])
        response = test_setup["client"].post(
            "/consent/requests",
            json={
                "request": req.model_dump(mode="json"),
                "requester_certificate_pem": certificate_to_pem(pki["bob_cert"]).decode(
                    "ascii"
                ),
            },
        )
        assert response.status_code == 403
        assert "SubjectCertificateError" in response.json()["detail"]

    def test_patient_certificate_cannot_stand_in_for_a_clinician(self, test_setup):
        """A patient certificate is not a clinician certificate (role check)."""
        pki = test_setup["pki"]
        req = create_consent_request(
            patient_id="patient-001",
            requester_id="patient-001",
            scope=("rec-001",),
            purpose="Consultation",
            requester_signing_key=pki["pat_priv"],
        )
        response = test_setup["client"].post(
            "/consent/requests",
            json={
                "request": req.model_dump(mode="json"),
                "requester_certificate_pem": pki["pat_cert_pem"],
            },
        )
        assert response.status_code == 403

    def test_submit_valid_consent_grant(self, test_setup):
        """Patient submits a valid signed grant."""
        pki = test_setup["pki"]
        grant = _grant(pki)

        response = test_setup["client"].post(
            "/consent/grants",
            json={
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pki["pat_cert_pem"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "accepted"
        assert data["grant"]["status"] == ConsentStatus.GRANTED.value

    def test_submit_forged_consent_grant_rejected(self, test_setup):
        """A grant not signed by the certified patient is rejected (400)."""
        pki = test_setup["pki"]
        foreign_priv, _ = generate_ec_keypair()
        grant = create_consent_grant(
            request=_signed_request(pki),
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=foreign_priv,  # forged/wrong signer
        )

        response = test_setup["client"].post(
            "/consent/grants",
            json={
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pki["pat_cert_pem"],
            },
        )

        assert response.status_code == 400
        assert "signature verification failed" in response.json()["detail"]

    def test_revocation_is_a_signed_revoked_grant(self, test_setup):
        """The patient's signed REVOKED grant is submitted like any decision;
        the facility's old key-taking revoke route is gone (ADR-0073)."""
        pki = test_setup["pki"]
        client = test_setup["client"]
        prior = _grant(pki)
        revoked = revoke_consent_grant(
            prior_grant=prior, patient_signing_key=pki["pat_priv"]
        )

        response = client.post(
            "/consent/grants",
            json={
                "grant": revoked.model_dump(mode="json"),
                "patient_certificate_pem": pki["pat_cert_pem"],
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "revoked"
        assert data["grant"]["status"] == ConsentStatus.REVOKED.value
        assert client.post("/consent/grants/revoke", json={}).status_code == 404

    def test_stale_granted_copy_cannot_undo_a_revocation(self, test_setup):
        """Review F13: once the request is revoked, re-submitting the old
        GRANTED grant -- still validly signed by the patient -- is refused and
        the store keeps the revocation (a revocation is a new grant answering
        the same request)."""
        pki = test_setup["pki"]
        client = test_setup["client"]
        prior = _grant(pki)
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
