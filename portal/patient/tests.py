"""Patient portal tests (P4-7, P4-10) -- SQLite settings, services mocked.

Run with::

    python manage.py test --settings=config.test_settings
"""

from __future__ import annotations

import base64
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from ledger.models import (
    ConsentRecord,
    ConsentStatus,
    NotificationKind,
    PatientNotification,
)
from portal_core.testing import (
    RECORD_META,
    SIGNED_REQUEST,
    SUBJECT_PATIENT,
    AuditLog,
    clinician,
    patched,
    patient,
    refuse,
    signed_grant,
)


class PatientRecordViewTests(TestCase):
    """Page 4: own record decrypts only through keys; fails closed otherwise."""

    def setUp(self) -> None:
        self.user = patient()
        self.client.login(username="alice", password="pw12345")

    def test_owner_read_streams_plaintext_for_this_request_only(self) -> None:
        payload = base64.b64encode(b'{"diagnosis": "AMI"}').decode()
        with mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META), patched(
            custodian_read=mock.Mock(
                return_value={
                    "plaintext_b64": payload,
                    "content_type": "application/json",
                    "access_via": "owner",
                    "attributes_presented": ["authority-net:owner:pat-101"],
                    "correlation_id": "owner-read-1",
                }
            ),
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ) as m:
            resp = self.client.post("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "AMI")
        self.assertEqual(resp["Cache-Control"], "no-store")
        m["custodian_read"].assert_called_once()
        self.assertEqual(m["custodian_read"].call_args.kwargs["facility_id"], "facility-a")
        # A GET afterwards shows nothing decrypted: nothing was persisted.
        with mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META), patched(
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)
        ):
            again = self.client.get("/patient/records/rec-001/")
        self.assertNotContains(again, "AMI")

    def test_login_without_owner_attribute_decrypts_nothing(self) -> None:
        """ADR-0016 / P5-1: the policy refusal is shown; no plaintext, no 500."""
        with mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META), patched(
            custodian_read=mock.Mock(side_effect=refuse(403, "record read: Policy denied: no path")),
            custodian_subject=mock.Mock(return_value=None),
        ):
            resp = self.client.post("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "access is not granted by keys", status_code=403)
        self.assertContains(resp, "Policy denied", status_code=403)
        self.assertNotContains(resp, "plaintext_b64", status_code=403)

    def test_login_with_no_key_agent_material_is_refused(self) -> None:
        """ADR-0021: a portal account alone grants zero access."""
        with mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META), patched(
            custodian_read=mock.Mock(side_effect=refuse(404, "no key material held for subject 'pat-101'")),
            custodian_subject=mock.Mock(return_value=None),
        ):
            resp = self.client.post("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "no key material", status_code=403)

    def test_another_patients_record_is_not_revealed(self) -> None:
        other = dict(RECORD_META, patient_id="pat-999")
        with mock.patch("portal_core.store_reader.record_meta", return_value=other):
            self.assertEqual(self.client.get("/patient/records/rec-001/").status_code, 404)
            self.assertEqual(self.client.post("/patient/records/rec-001/").status_code, 404)

    def test_store_outage_is_an_explicit_error_not_a_blank_page(self) -> None:
        with mock.patch("portal_core.store_reader.record_meta", side_effect=RuntimeError("db down")):
            resp = self.client.get("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 503)
        self.assertContains(resp, "Store unreachable", status_code=503)


class PatientConsentTests(TestCase):
    """Page 2: approve / deny / revoke sign through the custodian, verify at the facility."""

    def setUp(self) -> None:
        self.user = patient()
        clinician()
        self.client.login(username="alice", password="pw12345")
        self.row = ConsentRecord.objects.create(
            request_id=SIGNED_REQUEST["request_id"],
            patient_id="pat-101",
            requester_id="doc-201",
            requester_facility_id="facility-b",
            scope=["rec-001"],
            purpose="pre-op review",
            requested_at=timezone.now(),
            request_expires_at=timezone.now() + timedelta(days=7),
            request_json=SIGNED_REQUEST,
            correlation_id="consent-abc",
        )

    def test_pending_request_renders_with_sign_and_deny(self) -> None:
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)):
            resp = self.client.get("/patient/access/")
        self.assertContains(resp, "Sign grant")
        self.assertContains(resp, "pre-op review")

    def test_approve_signs_then_submits_to_requesters_facility(self) -> None:
        audit = AuditLog()
        with patched(
            custodian_decide_consent=mock.Mock(
                return_value={"grant": signed_grant("granted"), "patient_public_key_pem": "PEM"}
            ),
            facility_submit_grant=mock.Mock(return_value={"status": "accepted"}),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ) as m:
            resp = self.client.post(
                f"/patient/access/{self.row.request_id}/decide/", {"decision": "granted"}
            )
        self.assertEqual(resp.status_code, 302)
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, ConsentStatus.GRANTED)
        self.assertEqual(self.row.grant_json["status"], "granted")
        m["custodian_decide_consent"].assert_called_once_with(
            "pat-101", request=SIGNED_REQUEST, status="granted", ttl_days=5
        )
        m["facility_submit_grant"].assert_called_once()
        self.assertEqual(m["facility_submit_grant"].call_args.args[0], "facility-b")
        self.assertEqual(len(audit.of_type("consent.decision")), 1)

    def test_facility_refusing_the_grant_leaves_the_request_pending(self) -> None:
        with patched(
            custodian_decide_consent=mock.Mock(
                return_value={"grant": signed_grant("granted"), "patient_public_key_pem": "PEM"}
            ),
            facility_submit_grant=mock.Mock(
                side_effect=refuse(400, "Consent grant signature verification failed", "facility")
            ),
            audit_append=AuditLog(),
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ):
            self.client.post(f"/patient/access/{self.row.request_id}/decide/", {"decision": "granted"})
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, ConsentStatus.PENDING)
        self.assertIsNone(self.row.grant_json)

    def test_revoke_notifies_patient_and_enters_the_chain(self) -> None:
        """P4-10: a revocation produces a patient notification recorded in the audit log."""
        self.row.status = ConsentStatus.GRANTED
        self.row.grant_json = signed_grant("granted")
        self.row.save()
        audit = AuditLog()
        with patched(
            custodian_revoke_consent=mock.Mock(
                return_value={"grant": signed_grant("revoked"), "patient_public_key_pem": "PEM"}
            ),
            facility_submit_grant=mock.Mock(return_value={"status": "revoked"}),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ):
            resp = self.client.post(f"/patient/access/{self.row.request_id}/revoke/")
        self.assertEqual(resp.status_code, 302)
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, ConsentStatus.REVOKED)
        note = PatientNotification.objects.get(patient_id="pat-101", kind=NotificationKind.REVOKED)
        self.assertEqual(note.correlation_id, "consent-abc")
        self.assertIsNotNone(note.audit_seq)
        chain = audit.of_type("patient.notification")
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["event_data"]["kind"], "revoked")
        # Surfaced on the patient's home page.
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)), mock.patch(
            "portal_core.store_reader.records_for_patient", return_value=[]
        ):
            home = self.client.get("/patient/")
        self.assertContains(home, "was revoked")

    def test_only_a_live_grant_can_be_revoked(self) -> None:
        with patched(custodian_revoke_consent=mock.Mock()) as m:
            self.client.post(f"/patient/access/{self.row.request_id}/revoke/")
        m["custodian_revoke_consent"].assert_not_called()


class PatientHistoryAndRoleTests(TestCase):
    def test_break_glass_rows_are_badged(self) -> None:
        patient()
        self.client.login(username="alice", password="pw12345")
        entries = [
            {
                "seq": 7,
                "event_type": "federation.rewrap",
                "event_data": {"record_id": "rec-001", "target_actor_id": "doc-201"},
                "actor_id": "facility-b",
                "correlation_id": "lookup-1",
                "recorded_at": timezone.now(),
                "entry_hash_hex": "abcdef0123",
                "prev_hash_hex": "0",
            },
            {
                "seq": 8,
                "event_type": "access_denied",
                "event_data": {"record_id": "rec-001", "requester_id": "doc-301", "denied_by": "policy"},
                "actor_id": "facility-a",
                "correlation_id": "c2",
                "recorded_at": timezone.now(),
                "entry_hash_hex": "abcdef0124",
                "prev_hash_hex": "abcdef0123",
            },
        ]
        with mock.patch("portal_core.store_reader.records_for_patient", return_value=[RECORD_META]), mock.patch(
            "portal_core.store_reader.audit_for_patient", return_value=entries
        ), patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)):
            resp = self.client.get("/patient/history/?type=breakglass")
        self.assertContains(resp, "break-glass")
        self.assertNotContains(resp, "doc-301")

    def test_patient_is_routed_away_from_clinician_pages(self) -> None:
        patient()
        self.client.login(username="alice", password="pw12345")
        resp = self.client.get("/clinician/identify/")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].startswith("/patient/"))
