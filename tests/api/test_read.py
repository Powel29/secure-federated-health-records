"""Unit tests for the Hospital Node Read endpoint (P4-1).

Verifies:
- Read under valid patient consent grant.
- Read via patient owner attribute (ADR-0016).
- Fail-closed refusal when attributes are insufficient (PolicyDeniedError -> 403).
- Fail-closed refusal when consent grant is expired (ConsentExpiredError -> 403).
- Fail-closed refusal when consent grant is revoked (ConsentRevokedError -> 403).
- Fail-closed refusal when record is out of grant scope (ConsentScopeError -> 403).
- 404 when record does not exist.
"""

from __future__ import annotations

import base64
import datetime

from consent.service import create_consent_grant, create_consent_request
from contracts.enums import ConsentStatus
from crypto_core import (
    public_key_to_pem,
)


class TestHospitalReadEndpoint:
    """Test suite for POST /records/{record_id}/read."""

    def test_read_by_patient_with_owner_attribute(self, test_setup):
        """Patient directly decrypts own record via owner attribute (ADR-0016)."""
        client = test_setup["client"]
        attrs = test_setup["attrs"]

        # Only provide the owner attribute key
        owner_keyring = {
            "authority-net:owner:patient-001": attrs["b64_keyring"][
                "authority-net:owner:patient-001"
            ]
        }

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "patient-001",
                "holder_keyring": owner_keyring,
                "correlation_id": "corr-read-owner-001",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["record_id"] == "rec-001"
        assert data["patient_id"] == "patient-001"
        decrypted = base64.b64decode(data["plaintext_b64"])
        assert decrypted == test_setup["plaintext"]

    def test_read_under_valid_patient_consent(self, test_setup):
        """Clinician Alice reads record with valid consent and attributes."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        # 1. Alice creates consent request
        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Routine cardiology follow-up",
            requester_signing_key=pki["alice_priv"],
        )

        # 2. Patient signs grant approving Alice
        grant = create_consent_grant(
            request=req,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
            scope=("rec-001",),
        )

        # 3. Alice reads with clinical keyring and patient grant
        clinical_keyring = {
            "authority-med:role:physician": attrs["b64_keyring"][
                "authority-med:role:physician"
            ],
            "authority-net:specialty:cardiology": attrs["b64_keyring"][
                "authority-net:specialty:cardiology"
            ],
        }

        pat_pub_pem = public_key_to_pem(pki["pat_pub"]).decode("ascii")

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": clinical_keyring,
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
                "correlation_id": "corr-read-consent-001",
            },
        )

        assert response.status_code == 200
        data = response.json()
        decrypted = base64.b64decode(data["plaintext_b64"])
        assert decrypted == test_setup["plaintext"]

    def test_read_denied_when_attributes_insufficient(self, test_setup):
        """Clinician with missing attribute is refused decryption (403)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        # Only physician role, missing cardiology specialty
        incomplete_keyring = {
            "authority-med:role:physician": attrs["b64_keyring"][
                "authority-med:role:physician"
            ],
        }

        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Follow-up",
            requester_signing_key=pki["alice_priv"],
        )
        grant = create_consent_grant(
            request=req,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
            scope=("rec-001",),
        )
        pat_pub_pem = public_key_to_pem(pki["pat_pub"]).decode("ascii")

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": incomplete_keyring,
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
            },
        )

        assert response.status_code == 403
        assert "Policy denied" in response.json()["detail"]

    def test_read_denied_when_consent_grant_expired(self, test_setup):
        """Expired consent grant fails closed (403)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        now = datetime.datetime.now(datetime.timezone.utc)
        past = now - datetime.timedelta(days=10)

        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Follow-up",
            requester_signing_key=pki["alice_priv"],
            requested_at=past,
            ttl=datetime.timedelta(days=1),
        )
        grant = create_consent_grant(
            request=req,
            status=ConsentStatus.GRANTED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
            decided_at=past,
            ttl=datetime.timedelta(days=2),
        )
        pat_pub_pem = public_key_to_pem(pki["pat_pub"]).decode("ascii")

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": attrs["b64_keyring"],
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
            },
        )

        assert response.status_code == 403
        assert "Consent denied" in response.json()["detail"]

    def test_read_denied_when_grant_revoked(self, test_setup):
        """Revoked consent grant fails closed (403)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-001",),
            purpose="Follow-up",
            requester_signing_key=pki["alice_priv"],
        )
        grant = create_consent_grant(
            request=req,
            status=ConsentStatus.REVOKED,
            grantee_id="dr-alice",
            patient_signing_key=pki["pat_priv"],
        )
        pat_pub_pem = public_key_to_pem(pki["pat_pub"]).decode("ascii")

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": attrs["b64_keyring"],
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
            },
        )

        assert response.status_code == 403
        assert "revoked" in response.json()["detail"]

    def test_read_denied_when_scope_mismatch(self, test_setup):
        """Grant that does not cover rec-001 is refused (403)."""
        client = test_setup["client"]
        pki = test_setup["pki"]
        attrs = test_setup["attrs"]

        req = create_consent_request(
            patient_id="patient-001",
            requester_id="dr-alice",
            scope=("rec-999-other",),
            purpose="Follow-up",
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
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": attrs["b64_keyring"],
                "grant": grant.model_dump(mode="json"),
                "patient_public_key_pem": pat_pub_pem,
            },
        )

        assert response.status_code == 403
        assert "scope" in response.json()["detail"]

    def test_read_nonexistent_record_returns_404(self, test_setup):
        """Request for unknown record returns 404."""
        client = test_setup["client"]
        attrs = test_setup["attrs"]

        response = client.post(
            "/records/rec-nonexistent/read",
            json={
                "requester_id": "patient-001",
                "holder_keyring": attrs["b64_keyring"],
            },
        )
        assert response.status_code == 404
