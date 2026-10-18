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

from api.hospital import create_hospital_app
from consent.service import create_consent_grant, create_consent_request
from contracts.enums import ConsentStatus


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

        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": clinical_keyring,
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
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
        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": incomplete_keyring,
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
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
        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": attrs["b64_keyring"],
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
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
        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": attrs["b64_keyring"],
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
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
        pat_cert_pem = pki["pat_cert_pem"]

        response = client.post(
            "/records/rec-001/read",
            json={
                "requester_id": "dr-alice",
                "holder_keyring": attrs["b64_keyring"],
                "grant": grant.model_dump(mode="json"),
                "patient_certificate_pem": pat_cert_pem,
            },
        )

        assert response.status_code == 403
        assert "scope" in response.json()["detail"]

    def test_successful_read_fails_closed_when_audit_unreachable(self, test_setup):
        """Logging-as-precondition: a read that cannot be logged returns no plaintext.

        A successful owner read that would otherwise 200 instead returns 503 when
        the audit service is unreachable, because ``_log_granted`` is
        log-before-release (ARCHITECTURE.md §5). This is the negative test that
        proves the success-path log is a precondition, not best-effort.
        """
        # Same seeded repo, but this app points at an unreachable audit service.
        app = create_hospital_app(
            facility_id="facility-a",
            rotation_ports=test_setup["rotation"].ports,
            service_root=test_setup["pki"]["root"].certificate,
            repository=test_setup["repo"],
            expiry_manager=test_setup["expiry_manager"],
            audit_service_url="http://127.0.0.1:1",
            identity=test_setup["pki"]["services"].identity("facility-a"),
        )
        client = test_setup["pki"]["services"].client(
            app, "facility-a", raise_server_exceptions=False
        )
        attrs = test_setup["attrs"]

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
                "correlation_id": "corr-read-audit-down-001",
            },
        )

        assert response.status_code == 503
        assert "audit service unavailable" in response.json()["detail"]

    def test_read_without_audit_sink_returns_503_not_plaintext(self, test_setup):
        """Review F19: a facility with no audit destination releases nothing.

        Before the fix, ``_log_event`` silently did nothing when neither an
        audit URL nor an in-process logger was configured, so the read below
        returned plaintext with no log entry.
        """
        attrs = test_setup["attrs"]
        owner_keyring = {
            "authority-net:owner:patient-001": attrs["b64_keyring"][
                "authority-net:owner:patient-001"
            ]
        }
        body = {"requester_id": "patient-001", "holder_keyring": owner_keyring}

        # Setup is valid: with the fixture's audit sink the same read succeeds.
        assert (
            test_setup["client"].post("/records/rec-001/read", json=body).status_code
            == 200
        )

        app = create_hospital_app(
            facility_id="facility-a",
            rotation_ports=test_setup["rotation"].ports,
            service_root=test_setup["pki"]["root"].certificate,
            repository=test_setup["repo"],
            expiry_manager=test_setup["expiry_manager"],
        )
        response = (
            test_setup["pki"]["services"]
            .client(app, "facility-a")
            .post("/records/rec-001/read", json=body)
        )

        assert response.status_code == 503
        assert "plaintext_b64" not in response.text

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
