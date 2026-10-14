"""Clinician portal tests (P4-8, P4-8a) -- SQLite settings, services mocked."""

from __future__ import annotations

import base64
from datetime import date, timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from accounts.models import PatientDirectory
from ledger.models import (
    BreakglassCase,
    CaseStatus,
    ConsentRecord,
    ConsentStatus,
    NotificationKind,
    PatientNotification,
)
from portal_core.testing import (
    RECORD_META,
    SIGNED_REQUEST,
    SUBJECT_CLINICIAN,
    AuditLog,
    clinician,
    patched,
    patient,
    refuse,
)

UNLOCK = {
    "record_id": "rec-001",
    "patient_id": "pat-101",
    "facility_id": "facility-b",
    "clinician_id": "doc-201",
    "correlation_id": "lookup-11111111",
    "assertion_id": "9f2a0000-0000-0000-0000-000000000000",
    "assertion_expires_at": "2026-09-13T10:02:00+00:00",
    "shares_presented": [
        {"holder": "clinician", "x": 1, "audit_entry_seq": None},
        {"holder": "audit-service", "x": 3, "audit_entry_seq": 42},
    ],
    "transition_event": {"to_state": "emergency_open", "issued_at": "2026-09-13T10:00:00+00:00"},
    "opened_at": "2026-09-13T10:00:00+00:00",
    "expires_at": (timezone.now() + timedelta(seconds=120)).isoformat(),
    "content_type": "application/json",
    "plaintext_b64": base64.b64encode(b'{"allergies": ["Penicillin"]}').decode(),
}


def _directory() -> None:
    PatientDirectory.objects.create(
        subject_id="pat-101", given_name="Alice", family_name="Vance",
        date_of_birth=date(1982, 4, 15), home_authority_id="authority-net",
    )
    PatientDirectory.objects.create(
        subject_id="pat-777", given_name="Alicia", family_name="Vance",
        date_of_birth=date(1982, 4, 15), home_authority_id="authority-net",
    )


class IdentifyTests(TestCase):
    """P4-8a: name + DOB lookup, ambiguous matches shown, every lookup logged."""

    def setUp(self) -> None:
        clinician()
        _directory()
        self.client.login(username="house", password="pw12345")

    def test_ambiguous_match_shows_every_candidate_and_selects_none(self) -> None:
        audit = AuditLog()
        with patched(audit_append=audit, custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            resp = self.client.post(
                "/clinician/identify/", {"family_name": "Vance", "date_of_birth": "1982-04-15"}
            )
        self.assertContains(resp, "pat-101")
        self.assertContains(resp, "pat-777")
        self.assertContains(resp, "none auto-selected")
        self.assertNotIn("clinician.identified", self.client.session)
        lookups = audit.of_type("patient.lookup")
        self.assertEqual(len(lookups), 1)
        data = lookups[0]["event_data"]
        self.assertEqual(data["candidate_count"], 2)
        self.assertIsNone(data["selected_patient_id"])
        # PII never enters the chain: only a hash of the query.
        self.assertNotIn("Vance", str(lookups[0]))
        self.assertNotIn("1982", str(lookups[0]))

    def test_miss_is_logged_too(self) -> None:
        audit = AuditLog()
        with patched(audit_append=audit, custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            resp = self.client.post(
                "/clinician/identify/", {"family_name": "Nobody", "date_of_birth": "1970-01-01"}
            )
        self.assertContains(resp, "No directory match")
        self.assertEqual(audit.of_type("patient.lookup")[0]["event_data"]["candidate_count"], 0)

    def test_results_withheld_when_lookup_cannot_be_logged(self) -> None:
        with patched(audit_append=AuditLog(down=True), custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            resp = self.client.post(
                "/clinician/identify/", {"family_name": "Vance", "date_of_birth": "1982-04-15"}
            )
        self.assertEqual(resp.status_code, 503)
        self.assertNotContains(resp, "pat-101", status_code=503)
        self.assertContains(resp, "withheld", status_code=503)

    def test_selection_is_logged_and_carried_into_the_breakglass_form(self) -> None:
        audit = AuditLog()
        with patched(audit_append=audit, custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            self.client.post("/clinician/identify/", {"family_name": "Vance", "date_of_birth": "1982-04-15"})
            resp = self.client.post("/clinician/identify/select/", {"patient_id": "pat-777"})
        self.assertEqual(resp.status_code, 302)
        self.assertIn("patient_id=pat-777", resp["Location"])
        lookups = audit.of_type("patient.lookup")
        self.assertEqual(len(lookups), 2)
        self.assertEqual(lookups[1]["event_data"]["selected_patient_id"], "pat-777")
        self.assertEqual(lookups[0]["correlation_id"], lookups[1]["correlation_id"])
        self.assertEqual(self.client.session["clinician.identified"]["patient_id"], "pat-777")

    def test_cannot_select_an_id_that_was_not_a_candidate(self) -> None:
        audit = AuditLog()
        with patched(audit_append=audit, custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            self.client.post("/clinician/identify/", {"family_name": "Vance", "date_of_birth": "1982-04-15"})
            resp = self.client.post("/clinician/identify/select/", {"patient_id": "pat-999"})
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("clinician.identified", self.client.session)
        self.assertEqual(len(audit.of_type("patient.lookup")), 1)


class BreakglassTests(TestCase):
    def setUp(self) -> None:
        clinician()
        patient()
        _directory()
        self.client.login(username="house", password="pw12345")

    def _identify(self, audit: AuditLog) -> None:
        with patched(audit_append=audit, custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            self.client.post("/clinician/identify/", {"family_name": "Vance", "date_of_birth": "1982-04-15", "given_name": "Alice"})
            self.client.post("/clinician/identify/select/", {"patient_id": "pat-101"})

    def _token(self) -> str:
        return self.client.session["clinician.declare_token"]

    def _declare_mocks(self, audit: AuditLog, unlock: mock.Mock) -> object:
        return patched(
            facility_discover=mock.Mock(return_value=["rec-001"]),
            custodian_breakglass=unlock,
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        )

    def test_resubmitted_declaration_does_not_declare_again(self) -> None:
        """A replayed declare POST (reload, Back, expiry refresh) signs nothing and opens no second case."""
        audit = AuditLog()
        self._identify(audit)
        unlock = mock.Mock(return_value=UNLOCK)
        with self._declare_mocks(audit, unlock), mock.patch(
            "portal_core.store_reader.record_meta", return_value=RECORD_META
        ), mock.patch("portal_core.store_reader.audit_by_correlation", return_value=[]):
            self.client.post("/clinician/breakglass/", {"action": "discover", "patient_id": "pat-101"})
            form = {"action": "declare", "patient_id": "pat-101", "record_id": "rec-001",
                    "reason_code": "stroke", "declare_token": self._token()}
            first = self.client.post("/clinician/breakglass/", form)
            again = self.client.post("/clinician/breakglass/", form)
        # Setup was valid: the first declaration went through.
        self.assertEqual(first.status_code, 200)
        self.assertEqual(again.status_code, 409)
        self.assertContains(again, "already submitted", status_code=409)
        unlock.assert_called_once()
        self.assertEqual(BreakglassCase.objects.filter(record_id="rec-001").count(), 1)
        self.assertEqual(PatientNotification.objects.filter(kind=NotificationKind.BREAKGLASS).count(), 1)

    def test_declaration_without_a_form_token_is_refused(self) -> None:
        audit = AuditLog()
        self._identify(audit)
        unlock = mock.Mock(return_value=UNLOCK)
        with self._declare_mocks(audit, unlock), mock.patch(
            "portal_core.store_reader.record_meta", return_value=RECORD_META
        ):
            self.client.post("/clinician/breakglass/", {"action": "discover", "patient_id": "pat-101"})
            resp = self.client.post(
                "/clinician/breakglass/",
                {"action": "declare", "patient_id": "pat-101", "record_id": "rec-001", "reason_code": "stroke"},
            )
        self.assertEqual(resp.status_code, 409)
        unlock.assert_not_called()
        self.assertFalse(BreakglassCase.objects.exists())

    def test_case_page_refreshes_to_its_own_url_at_expiry(self) -> None:
        """The expiry refresh is a GET of the case, never a reload of the declare POST."""
        case = BreakglassCase.objects.create(
            correlation_id="lookup-z", record_id="rec-001", patient_id="pat-101", clinician_id="doc-201",
            facility_id="facility-b", reason_code="stroke", status=CaseStatus.OPEN,
            opened_at=timezone.now(), expires_at=timezone.now() + timedelta(minutes=2),
        )
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)), mock.patch(
            "portal_core.store_reader.audit_by_correlation", return_value=[]
        ):
            resp = self.client.get(f"/clinician/cases/{case.pk}/")
        self.assertContains(resp, f'setAttribute("data-reload-on-expiry", "/clinician/cases/{case.pk}/")')
        self.assertNotContains(resp, "location.reload()")

    def test_declaration_without_identification_is_refused(self) -> None:
        with patched(custodian_breakglass=mock.Mock(), custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)) as m:
            resp = self.client.post("/clinician/breakglass/", {"action": "declare", "reason_code": "stroke"})
        self.assertEqual(resp.status_code, 400)
        m["custodian_breakglass"].assert_not_called()

    def test_successful_breakglass_creates_case_notifies_patient_shows_payload_once(self) -> None:
        audit = AuditLog()
        self._identify(audit)
        with patched(
            facility_discover=mock.Mock(return_value=["rec-001"]),
            custodian_breakglass=mock.Mock(return_value=UNLOCK),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ) as m, mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META), mock.patch(
            "portal_core.store_reader.audit_by_correlation", return_value=[]
        ):
            disc = self.client.post("/clinician/breakglass/", {"action": "discover", "patient_id": "pat-101"})
            self.assertContains(disc, "rec-001")
            resp = self.client.post(
                "/clinician/breakglass/",
                {"action": "declare", "patient_id": "pat-101", "record_id": "rec-001",
                 "reason_code": "unconscious_patient", "justification": "Unresponsive on arrival.",
                 "declare_token": self._token()},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Penicillin")  # shown on this response only
        self.assertEqual(resp["Cache-Control"], "no-store")
        # The assertion was bound to the identified patient under the lookup's correlation id.
        kwargs = m["custodian_breakglass"].call_args.kwargs
        self.assertEqual(kwargs["patient_id"], "pat-101")
        self.assertTrue(kwargs["correlation_id"].startswith("lookup-"))
        case = BreakglassCase.objects.get(record_id="rec-001")
        self.assertEqual(case.status, CaseStatus.OPEN)
        self.assertEqual(case.audit_entry_seq, 42)
        # P4-10: the patient is notified and the notification is in the chain.
        note = PatientNotification.objects.get(patient_id="pat-101", kind=NotificationKind.BREAKGLASS)
        self.assertEqual(note.correlation_id, UNLOCK["correlation_id"])
        self.assertEqual(audit.of_type("patient.notification")[0]["event_data"]["kind"], "breakglass")
        # Reloading the case never shows the payload again.
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)), mock.patch(
            "portal_core.store_reader.audit_by_correlation", return_value=[]
        ):
            again = self.client.get(f"/clinician/cases/{case.pk}/")
        self.assertEqual(again.status_code, 200)
        self.assertNotContains(again, "Penicillin")
        self.assertContains(again, "Threshold collection")

    def test_failed_unlock_is_recorded_as_failed_closed_and_nobody_is_notified(self) -> None:
        audit = AuditLog()
        self._identify(audit)
        with patched(
            facility_discover=mock.Mock(return_value=["rec-001"]),
            custodian_breakglass=mock.Mock(
                side_effect=refuse(503, "audit share release: log commit failed; share was not released")
            ),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ), mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META):
            self.client.post("/clinician/breakglass/", {"action": "discover", "patient_id": "pat-101"})
            resp = self.client.post(
                "/clinician/breakglass/",
                {"action": "declare", "patient_id": "pat-101", "record_id": "rec-001", "reason_code": "stroke",
                 "declare_token": self._token()},
            )
        self.assertEqual(resp.status_code, 503)
        self.assertContains(resp, "share was not released", status_code=503)
        case = BreakglassCase.objects.get(record_id="rec-001")
        self.assertEqual(case.status, CaseStatus.FAILED)
        self.assertFalse(PatientNotification.objects.filter(kind=NotificationKind.BREAKGLASS).exists())

    def test_emergency_search_after_expiry_reports_dead_token(self) -> None:
        case = BreakglassCase.objects.create(
            correlation_id="lookup-x", record_id="rec-001", patient_id="pat-101", clinician_id="doc-201",
            facility_id="facility-b", reason_code="stroke", status=CaseStatus.OPEN,
            opened_at=timezone.now() - timedelta(minutes=5), expires_at=timezone.now() - timedelta(minutes=3),
        )
        with patched(
            facility_emergency_search=mock.Mock(side_effect=refuse(403, "Emergency search unavailable: expired", "facility")),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ), mock.patch("portal_core.store_reader.audit_by_correlation", return_value=[]):
            resp = self.client.post(f"/clinician/cases/{case.pk}/", {"search_term": "cardiac"})
        self.assertContains(resp, "expired")
        case.refresh_from_db()
        self.assertEqual(case.status, CaseStatus.EXPIRED)

    def test_in_page_search_returns_only_the_search_card(self) -> None:
        case = BreakglassCase.objects.create(
            correlation_id="lookup-y", record_id="rec-001", patient_id="pat-101", clinician_id="doc-201",
            facility_id="facility-b", reason_code="stroke", status=CaseStatus.OPEN,
            opened_at=timezone.now(), expires_at=timezone.now() + timedelta(minutes=2),
        )
        with patched(
            facility_emergency_search=mock.Mock(return_value=["rec-001"]),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ), mock.patch("portal_core.store_reader.audit_by_correlation", return_value=[]):
            resp = self.client.post(
                f"/clinician/cases/{case.pk}/", {"search_term": "cardiac"}, HTTP_X_REQUESTED_WITH="fetch"
            )
        self.assertContains(resp, 'id="emergency-search"')
        self.assertContains(resp, 'HKDF(emergency key, "cardiac")')
        # Only the card: the page around it (and any record shown there) is untouched.
        self.assertNotContains(resp, "Threshold collection")
        self.assertNotContains(resp, "<html")


class ConsentReadTests(TestCase):
    def setUp(self) -> None:
        clinician()
        self.client.login(username="house", password="pw12345")
        self.row = ConsentRecord.objects.create(
            request_id=SIGNED_REQUEST["request_id"], patient_id="pat-101", requester_id="doc-201",
            requester_facility_id="facility-b", scope=["rec-001"], purpose="pre-op",
            requested_at=timezone.now(), request_expires_at=timezone.now() + timedelta(days=7),
            request_json=SIGNED_REQUEST, correlation_id="consent-abc",
        )

    def test_pending_grant_reads_nothing(self) -> None:
        """A portal login with a request but no patient-signed grant decrypts nothing."""
        with patched(custodian_read=mock.Mock(), custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)) as m:
            resp = self.client.post(f"/clinician/consent/{self.row.request_id}/read/")
        self.assertEqual(resp.status_code, 403)
        m["custodian_read"].assert_not_called()

    def test_policy_denial_under_a_live_grant_is_shown_verbatim(self) -> None:
        self.row.status = ConsentStatus.GRANTED
        self.row.grant_json = {"status": "granted", "grant_id": "g"}
        self.row.save()
        with patched(
            custodian_read=mock.Mock(side_effect=refuse(403, "record read: Policy denied: no satisfying path")),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ), mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META):
            resp = self.client.post(f"/clinician/consent/{self.row.request_id}/read/")
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "Policy denied", status_code=403)

    def test_request_is_signed_by_custodian_and_patient_is_notified(self) -> None:
        patient()
        audit = AuditLog()
        with patched(
            facility_discover=mock.Mock(return_value=["rec-001"]),
            custodian_sign_consent_request=mock.Mock(return_value=dict(SIGNED_REQUEST, request_id="1d1d1d1d-0000-4000-8000-000000000001")),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ) as m, mock.patch("portal_core.store_reader.record_meta", return_value=RECORD_META):
            self.client.post("/clinician/consent/", {"action": "discover", "patient_id": "pat-101"})
            resp = self.client.post(
                "/clinician/consent/",
                {"action": "request", "patient_id": "pat-101", "scope": ["rec-001"], "purpose": "pre-op"},
            )
        self.assertEqual(resp.status_code, 302)
        m["custodian_sign_consent_request"].assert_called_once()
        self.assertTrue(ConsentRecord.objects.filter(request_id="1d1d1d1d-0000-4000-8000-000000000001").exists())
        self.assertTrue(PatientNotification.objects.filter(patient_id="pat-101", kind=NotificationKind.CONSENT_REQUEST).exists())
