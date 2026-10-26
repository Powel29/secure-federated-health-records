"""Clinician portal tests (P4-8, P4-8a) -- SQLite settings, services mocked."""

from __future__ import annotations

import base64
from datetime import date, timedelta
from unittest import mock

from accounts.models import PatientDirectory
from django.test import TestCase
from django.utils import timezone
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
    TEST_PASSWORD,
    AuditLog,
    clinician,
    declare_token,
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
    "transition_event": {
        "to_state": "emergency_open",
        "issued_at": "2026-09-13T10:00:00+00:00",
    },
    "opened_at": "2026-09-13T10:00:00+00:00",
    "expires_at": (timezone.now() + timedelta(seconds=120)).isoformat(),
    "content_type": "application/json",
    "plaintext_b64": base64.b64encode(b'{"allergies": ["Penicillin"]}').decode(),
}


def _directory() -> None:
    PatientDirectory.objects.create(
        subject_id="pat-101",
        given_name="Alice",
        family_name="Vance",
        date_of_birth=date(1982, 4, 15),
        home_authority_id="authority-net",
    )
    PatientDirectory.objects.create(
        subject_id="pat-777",
        given_name="Alicia",
        family_name="Vance",
        date_of_birth=date(1982, 4, 15),
        home_authority_id="authority-net",
    )


class IdentifyTests(TestCase):
    """P4-8a: name + DOB lookup, ambiguous matches shown, every lookup logged."""

    def setUp(self) -> None:
        clinician()
        _directory()
        self.client.login(username="house", password=TEST_PASSWORD)

    def test_ambiguous_match_shows_every_candidate_and_selects_none(self) -> None:
        audit = AuditLog()
        with patched(
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            resp = self.client.post(
                "/clinician/identify/",
                {"family_name": "Vance", "date_of_birth": "1982-04-15"},
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
        # PII never enters the chain (ADR-0085).
        self.assertNotIn("Vance", str(lookups[0]))
        self.assertNotIn("1982", str(lookups[0]))

    def test_lookup_entry_records_nothing_about_what_was_typed(self) -> None:
        """ARCHITECTURE §8 / ADR-0085: no name or date of birth reaches the
        chain in any form. Two lookups that surface the same candidates must
        log identical entries, so no field may depend on the query -- a hash
        of it included, since names and dates are easy to brute-force."""
        same_hits = [
            {"family_name": "Vance", "date_of_birth": "1982-04-15"},
            {"family_name": "vance"},
        ]
        same_misses = [
            {"family_name": "Nobody", "date_of_birth": "1970-01-01"},
            {"family_name": "Smith", "given_name": "Jo", "date_of_birth": "1999-12-31"},
        ]
        audit = AuditLog()
        with patched(
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            for query in same_hits + same_misses:
                self.client.post("/clinician/identify/", query)
        lookups = [e["event_data"] for e in audit.of_type("patient.lookup")]

        # Positive control: every lookup was logged with the expected outcome.
        self.assertEqual([d["candidate_count"] for d in lookups], [2, 2, 0, 0])
        self.assertEqual(lookups[0]["candidate_ids"], ["pat-101", "pat-777"])

        self.assertEqual(lookups[0], lookups[1])
        self.assertEqual(lookups[2], lookups[3])
        logged = str(audit.entries).lower()
        for typed in (
            "vance", "alice", "alicia", "nobody", "smith", "1982-04-15",
            "15/04/1982", "04/15/1982", "19820415", "1970-01-01", "1999-12-31",
        ):  # fmt: skip
            self.assertNotIn(typed, logged)

    def test_miss_is_logged_too(self) -> None:
        audit = AuditLog()
        with patched(
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            resp = self.client.post(
                "/clinician/identify/",
                {"family_name": "Nobody", "date_of_birth": "1970-01-01"},
            )
        self.assertContains(resp, "No directory match")
        self.assertEqual(
            audit.of_type("patient.lookup")[0]["event_data"]["candidate_count"], 0
        )

    def test_results_withheld_when_lookup_cannot_be_logged(self) -> None:
        with patched(
            audit_append=AuditLog(down=True),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            resp = self.client.post(
                "/clinician/identify/",
                {"family_name": "Vance", "date_of_birth": "1982-04-15"},
            )
        self.assertEqual(resp.status_code, 503)
        self.assertNotContains(resp, "pat-101", status_code=503)
        self.assertContains(resp, "withheld", status_code=503)

    def test_selection_is_logged_and_carried_into_the_breakglass_form(self) -> None:
        audit = AuditLog()
        with patched(
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            self.client.post(
                "/clinician/identify/",
                {"family_name": "Vance", "date_of_birth": "1982-04-15"},
            )
            resp = self.client.post(
                "/clinician/identify/select/", {"patient_id": "pat-777"}
            )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("patient_id=pat-777", resp["Location"])
        lookups = audit.of_type("patient.lookup")
        self.assertEqual(len(lookups), 2)
        self.assertEqual(lookups[1]["event_data"]["selected_patient_id"], "pat-777")
        self.assertEqual(lookups[0]["correlation_id"], lookups[1]["correlation_id"])
        self.assertEqual(
            self.client.session["clinician.identified"]["patient_id"], "pat-777"
        )

    def test_cannot_select_an_id_that_was_not_a_candidate(self) -> None:
        audit = AuditLog()
        with patched(
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            self.client.post(
                "/clinician/identify/",
                {"family_name": "Vance", "date_of_birth": "1982-04-15"},
            )
            resp = self.client.post(
                "/clinician/identify/select/", {"patient_id": "pat-999"}
            )
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("clinician.identified", self.client.session)
        self.assertEqual(len(audit.of_type("patient.lookup")), 1)


class BreakglassTests(TestCase):
    def setUp(self) -> None:
        clinician()
        patient()
        _directory()
        self.client.login(username="house", password=TEST_PASSWORD)

    def _identify(self, audit: AuditLog) -> None:
        with patched(
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            self.client.post(
                "/clinician/identify/",
                {
                    "family_name": "Vance",
                    "date_of_birth": "1982-04-15",
                    "given_name": "Alice",
                },
            )
            self.client.post("/clinician/identify/select/", {"patient_id": "pat-101"})

    def test_breakglass_without_lookup_refused(self) -> None:
        """Review F41: a raw patient_id cannot skip the logged lookup."""
        with patched(
            custodian_breakglass=mock.Mock(),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ) as m:
            resp = self.client.post(
                "/clinician/breakglass/",
                {
                    "action": "declare",
                    "patient_id": "pat-101",
                    "record_id": "rec-001",
                    "reason_code": "stroke",
                    "justification": "Immediate stroke treatment requires the medication history.",
                },
            )
        self.assertEqual(resp.status_code, 400)
        self.assertContains(resp, "logged directory lookup", status_code=400)
        m["custodian_breakglass"].assert_not_called()

    def test_breakglass_for_a_different_patient_than_selected_refused(self) -> None:
        audit = AuditLog()
        self._identify(audit)  # selects pat-101
        with patched(
            custodian_breakglass=mock.Mock(),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ) as m:
            resp = self.client.post(
                "/clinician/breakglass/",
                {
                    "action": "declare",
                    "patient_id": "pat-202",
                    "record_id": "rec-009",
                    "reason_code": "stroke",
                },
            )
        self.assertEqual(resp.status_code, 400)
        m["custodian_breakglass"].assert_not_called()

    def test_declaration_without_identification_is_refused(self) -> None:
        with patched(
            custodian_breakglass=mock.Mock(),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ) as m:
            resp = self.client.post(
                "/clinician/breakglass/", {"action": "declare", "reason_code": "stroke"}
            )
        self.assertEqual(resp.status_code, 400)
        m["custodian_breakglass"].assert_not_called()

    def test_successful_breakglass_creates_case_notifies_patient_shows_payload(
        self,
    ) -> None:
        audit = AuditLog()
        self._identify(audit)
        with (
            patched(
                facility_discover=mock.Mock(return_value=["rec-001"]),
                custodian_breakglass=mock.Mock(return_value=UNLOCK),
                audit_append=audit,
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
            ) as m,
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=[]
            ),
        ):
            disc = self.client.post(
                "/clinician/breakglass/",
                {"action": "discover", "patient_id": "pat-101"},
            )
            self.assertContains(disc, "rec-001")
            resp = self.client.post(
                "/clinician/breakglass/",
                {
                    "action": "declare",
                    "declare_token": declare_token(disc),
                    "patient_id": "pat-101",
                    "record_id": "rec-001",
                    "reason_code": "unconscious_patient",
                    "justification": "Unresponsive on arrival.",
                },
            )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Penicillin")
        self.assertEqual(resp["Cache-Control"], "no-store")
        # The assertion binds the identified patient and lookup correlation id.
        kwargs = m["custodian_breakglass"].call_args.kwargs
        self.assertEqual(kwargs["patient_id"], "pat-101")
        self.assertTrue(kwargs["correlation_id"].startswith("lookup-"))
        case = BreakglassCase.objects.get(record_id="rec-001")
        self.assertEqual(case.status, CaseStatus.OPEN)
        self.assertEqual(case.audit_entry_seq, 42)
        # P4-10: the patient is notified and the notification is in the chain.
        note = PatientNotification.objects.get(
            patient_id="pat-101", kind=NotificationKind.BREAKGLASS
        )
        self.assertEqual(note.correlation_id, UNLOCK["correlation_id"])
        self.assertEqual(
            audit.of_type("patient.notification")[0]["event_data"]["kind"], "breakglass"
        )
        # Opening the case again shows the record through a fresh audited join.
        with (
            patched(
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
                custodian_breakglass=mock.Mock(return_value={**UNLOCK, "joined": True}),
            ) as again_m,
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=[]
            ),
        ):
            again = self.client.get(f"/clinician/cases/{case.pk}/")
        self.assertEqual(again.status_code, 200)
        self.assertContains(again, "Penicillin")
        self.assertContains(again, "Threshold collection")
        self.assertEqual(
            again_m["custodian_breakglass"].call_args.kwargs["correlation_id"],
            case.correlation_id,
        )

    def test_failed_unlock_is_recorded_as_failed_closed_and_nobody_is_notified(
        self,
    ) -> None:
        audit = AuditLog()
        self._identify(audit)
        with (
            patched(
                facility_discover=mock.Mock(return_value=["rec-001"]),
                custodian_breakglass=mock.Mock(
                    side_effect=refuse(
                        503,
                        "audit share release: log commit failed; "
                        "share was not released",
                    )
                ),
                audit_append=audit,
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
            ),
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
        ):
            disc = self.client.post(
                "/clinician/breakglass/",
                {"action": "discover", "patient_id": "pat-101"},
            )
            resp = self.client.post(
                "/clinician/breakglass/",
                {
                    "action": "declare",
                    "declare_token": declare_token(disc),
                    "patient_id": "pat-101",
                    "record_id": "rec-001",
                    "reason_code": "stroke",
                    "justification": "Immediate stroke treatment needs medication history.",
                },
            )
        self.assertEqual(resp.status_code, 503)
        self.assertContains(resp, "share was not released", status_code=503)
        case = BreakglassCase.objects.get(record_id="rec-001")
        self.assertEqual(case.status, CaseStatus.FAILED)
        self.assertFalse(
            PatientNotification.objects.filter(
                kind=NotificationKind.BREAKGLASS
            ).exists()
        )

    def test_emergency_search_after_expiry_reports_dead_token(self) -> None:
        case = BreakglassCase.objects.create(
            correlation_id="lookup-x",
            record_id="rec-001",
            patient_id="pat-101",
            clinician_id="doc-201",
            facility_id="facility-b",
            reason_code="stroke",
            status=CaseStatus.OPEN,
            opened_at=timezone.now() - timedelta(minutes=5),
            expires_at=timezone.now() - timedelta(minutes=3),
        )
        with (
            patched(
                facility_emergency_search=mock.Mock(
                    side_effect=refuse(
                        403, "Emergency search unavailable: expired", "facility"
                    )
                ),
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
            ),
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=[]
            ),
        ):
            resp = self.client.post(
                f"/clinician/cases/{case.pk}/", {"search_term": "cardiac"}
            )
        self.assertContains(resp, "expired")
        case.refresh_from_db()
        self.assertEqual(case.status, CaseStatus.EXPIRED)


class RedeclareLoopTests(TestCase):
    """ADR-0065: a reloaded or re-sent declaration opens nothing a second time.

    The case page used to be the response to the declare POST, and its expiry
    refresh called ``location.reload()`` -- which re-sends that POST, so every
    window opened a new break-glass, re-released shares 3 and 4 and re-notified the
    patient.
    """

    def setUp(self) -> None:
        clinician()
        patient()
        _directory()
        self.client.login(username="house", password=TEST_PASSWORD)
        self.audit = AuditLog()
        with patched(
            audit_append=self.audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ):
            self.client.post(
                "/clinician/identify/",
                {
                    "family_name": "Vance",
                    "date_of_birth": "1982-04-15",
                    "given_name": "Alice",
                },
            )
            self.client.post("/clinician/identify/select/", {"patient_id": "pat-101"})
        self.services = self.enterContext(
            patched(
                facility_discover=mock.Mock(return_value=["rec-001"]),
                custodian_breakglass=mock.Mock(return_value=UNLOCK),
                audit_append=self.audit,
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
            )
        )
        self.enterContext(
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            )
        )
        self.enterContext(
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=[]
            )
        )
        disc = self.client.post(
            "/clinician/breakglass/", {"action": "discover", "patient_id": "pat-101"}
        )
        self.declaration = {
            "action": "declare",
            "declare_token": declare_token(disc),
            "patient_id": "pat-101",
            "record_id": "rec-001",
            "reason_code": "unconscious_patient",
            "justification": "Unresponsive on arrival; needs allergy history now.",
        }

    def _breakglass_notifications(self) -> int:
        return PatientNotification.objects.filter(
            kind=NotificationKind.BREAKGLASS
        ).count()

    def test_resent_declaration_is_refused_and_opens_nothing(self) -> None:
        first = self.client.post("/clinician/breakglass/", self.declaration)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(self.services["custodian_breakglass"].call_count, 1)

        # What the old expiry reload did: the same POST, sent again.
        again = self.client.post("/clinician/breakglass/", self.declaration)
        self.assertEqual(again.status_code, 409)
        self.assertContains(again, "already sent", status_code=409)
        self.assertEqual(self.services["custodian_breakglass"].call_count, 1)
        self.assertEqual(BreakglassCase.objects.count(), 1)
        self.assertEqual(self._breakglass_notifications(), 1)

    def test_declaration_without_a_token_is_refused(self) -> None:
        no_token = {k: v for k, v in self.declaration.items() if k != "declare_token"}
        resp = self.client.post("/clinician/breakglass/", no_token)
        self.assertEqual(resp.status_code, 409)
        self.services["custodian_breakglass"].assert_not_called()
        self.assertFalse(BreakglassCase.objects.exists())
        self.assertEqual(self._breakglass_notifications(), 0)

    def test_a_forged_token_is_refused(self) -> None:
        forged = {**self.declaration, "declare_token": "not-the-session-token"}
        resp = self.client.post("/clinician/breakglass/", forged)
        self.assertEqual(resp.status_code, 409)
        self.services["custodian_breakglass"].assert_not_called()

    def test_case_page_refreshes_to_its_own_url_not_the_post(self) -> None:
        resp = self.client.post("/clinician/breakglass/", self.declaration)
        case = BreakglassCase.objects.get()
        case_url = f"/clinician/cases/{case.pk}/"
        body = resp.content.decode("utf-8")
        # The expiry refresh navigates to the case URL (a GET) ...
        self.assertIn(f'setAttribute("data-reload-on-expiry", "{case_url}")', body)
        self.assertIn("window.location.replace(reload)", body)
        self.assertNotIn("window.location.reload()", body)
        # ... and the address bar already shows it, so a manual reload is a GET.
        self.assertIn(f'history.replaceState(null, "", "{case_url}")', body)

    def test_viewing_a_case_only_joins_and_never_opens(self) -> None:
        self.client.post("/clinician/breakglass/", self.declaration)
        case = BreakglassCase.objects.get()
        self.services["custodian_breakglass"].reset_mock()
        self.client.get(f"/clinician/cases/{case.pk}/")
        self.assertIs(
            self.services["custodian_breakglass"].call_args.kwargs["join_only"], True
        )


class ViewOnOpenTests(TestCase):
    """Opening a live case shows the record through the custodian, every time."""

    def setUp(self) -> None:
        self.client.force_login(clinician())
        self.case = BreakglassCase.objects.create(
            correlation_id="lookup-view-again",
            record_id="rec-001",
            patient_id="pat-101",
            clinician_id="doc-201",
            facility_id="facility-b",
            reason_code="stroke",
            status=CaseStatus.OPEN,
            opened_at=timezone.now() - timedelta(minutes=1),
            expires_at=timezone.now() + timedelta(minutes=10),
        )
        self.url = f"/clinician/cases/{self.case.pk}/"
        self.services = self.enterContext(
            patched(
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
                custodian_breakglass=mock.Mock(return_value={**UNLOCK, "joined": True}),
                facility_emergency_search=mock.Mock(),
                audit_append=AuditLog(),
            )
        )
        self.enterContext(
            mock.patch("portal_core.store_reader.audit_by_correlation", return_value=[])
        )

    def test_opening_a_live_case_shows_the_record_without_persisting_it(
        self,
    ) -> None:
        before = BreakglassCase.objects.values().get(pk=self.case.pk)
        page = self.client.get(self.url, {"patient_id": "pat-other"})
        self.assertContains(page, "Penicillin")
        self.assertNotContains(page, "View record again")
        self.assertEqual(page["Cache-Control"], "no-store")
        # Query parameters cannot override the case's patient or clinician.
        self.services["custodian_breakglass"].assert_called_once_with(
            self.case.clinician_id,
            patient_id=self.case.patient_id,
            record_id=self.case.record_id,
            reason_code=self.case.reason_code,
            correlation_id=self.case.correlation_id,
            facility_id=self.case.facility_id,
            justification=self.case.justification,
            sensitive_justification=self.case.sensitive_justification,
            join_only=True,
        )
        self.services["facility_emergency_search"].assert_not_called()
        self.assertEqual(BreakglassCase.objects.count(), 1)
        self.assertEqual(BreakglassCase.objects.values().get(pk=self.case.pk), before)
        self.assertFalse(PatientNotification.objects.exists())
        self.assertNotIn("Penicillin", str(dict(self.client.session)))
        self.assertNotIn(UNLOCK["plaintext_b64"], str(dict(self.client.session)))
        # Every load is its own audited join; nothing is cached between them.
        self.assertContains(self.client.get(self.url), "Penicillin")
        self.assertEqual(self.services["custodian_breakglass"].call_count, 2)

    def test_binary_records_are_embedded_or_downloaded_never_dumped_as_text(
        self,
    ) -> None:
        pdf = b"%PDF-1.3 synthetic test document"
        html = b"<script>alert(1)</script>"
        cases = {
            "application/pdf": (
                pdf,
                '<iframe class="record-embed" src="data:application/pdf;base64,',
            ),
            "image/png": (
                b"PNG synthetic",
                '<img class="record-embed-image" src="data:image/png;base64,',
            ),
            # Text types stay escaped text; other binaries become a download.
            "text/html; charset=utf-8": (html, "&lt;script&gt;alert(1)&lt;/script&gt;"),
            "application/zip": (b"PK zip", "data:application/octet-stream;base64,"),
        }
        for content_type, (payload, expected) in cases.items():
            with self.subTest(content_type):
                self.services["custodian_breakglass"].return_value = {
                    **UNLOCK,
                    "joined": True,
                    "content_type": content_type,
                    "plaintext_b64": base64.b64encode(payload).decode(),
                }
                page = self.client.get(self.url)
                self.assertContains(page, expected)
                self.assertNotContains(page, "%PDF-1.3")
                self.assertNotContains(page, "<script>alert(1)</script>")
                if not content_type.startswith("text/"):
                    self.assertNotContains(page, '<pre class="plaintext">')

    def test_elapsed_window_shows_no_record_and_skips_the_custodian(self) -> None:
        self.case.expires_at = timezone.now() - timedelta(seconds=1)
        self.case.save(update_fields=["expires_at"])
        response = self.client.get(self.url)
        self.assertNotContains(response, "Penicillin")
        self.services["custodian_breakglass"].assert_not_called()
        self.case.refresh_from_db()
        self.assertEqual(self.case.status, CaseStatus.EXPIRED)

    def test_closed_cases_show_no_record_even_with_a_future_expiry(self) -> None:
        for status in (CaseStatus.EXPIRED, CaseStatus.FAILED):
            with self.subTest(status=status):
                self.case.status = status
                self.case.save(update_fields=["status"])
                response = self.client.get(self.url)
                self.assertNotContains(response, "Penicillin")
                self.services["custodian_breakglass"].assert_not_called()

    def test_upstream_denial_or_outage_shows_no_plaintext(self) -> None:
        for status, detail in (
            (403, "Emergency session expired"),
            (503, "Audit share was not released"),
        ):
            with self.subTest(status=status):
                self.services["custodian_breakglass"].side_effect = refuse(
                    status, detail
                )
                response = self.client.get(self.url)
                self.assertContains(response, detail, status_code=status)
                self.assertNotContains(response, "Penicillin", status_code=status)
                self.assertFalse(PatientNotification.objects.exists())

    def test_another_clinician_cannot_view_the_case(self) -> None:
        self.client.force_login(clinician("other", "doc-other"))
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)
        self.services["custodian_breakglass"].assert_not_called()


class ConsentReadTests(TestCase):
    def setUp(self) -> None:
        clinician()
        self.client.login(username="house", password=TEST_PASSWORD)
        self.row = ConsentRecord.objects.create(
            request_id=SIGNED_REQUEST["request_id"],
            patient_id="pat-101",
            requester_id="doc-201",
            requester_facility_id="facility-b",
            scope=["rec-001"],
            purpose="pre-op",
            requested_at=timezone.now(),
            request_expires_at=timezone.now() + timedelta(days=7),
            request_json=SIGNED_REQUEST,
            correlation_id="consent-abc",
        )

    def test_pending_grant_reads_nothing(self) -> None:
        """A login and request without a patient-signed grant decrypt nothing."""
        with patched(
            custodian_read=mock.Mock(),
            custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
        ) as m:
            resp = self.client.post(f"/clinician/consent/{self.row.request_id}/read/")
        self.assertEqual(resp.status_code, 403)
        m["custodian_read"].assert_not_called()

    def test_policy_denial_under_a_live_grant_is_shown_verbatim(self) -> None:
        self.row.status = ConsentStatus.GRANTED
        self.row.grant_json = {"status": "granted", "grant_id": "g"}
        self.row.save()
        with (
            patched(
                custodian_read=mock.Mock(
                    side_effect=refuse(
                        403, "record read: Policy denied: no satisfying path"
                    )
                ),
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
            ),
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
        ):
            resp = self.client.post(f"/clinician/consent/{self.row.request_id}/read/")
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "Policy denied", status_code=403)

    def test_request_is_signed_by_custodian_and_patient_is_notified(self) -> None:
        patient()
        audit = AuditLog()
        with (
            patched(
                facility_discover=mock.Mock(return_value=["rec-001"]),
                custodian_sign_consent_request=mock.Mock(
                    return_value=dict(
                        SIGNED_REQUEST,
                        request_id="1d1d1d1d-0000-4000-8000-000000000001",
                    )
                ),
                audit_append=audit,
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
            ) as m,
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
        ):
            self.client.post(
                "/clinician/consent/", {"action": "discover", "patient_id": "pat-101"}
            )
            resp = self.client.post(
                "/clinician/consent/",
                {
                    "action": "request",
                    "patient_id": "pat-101",
                    "scope": ["rec-001"],
                    "purpose": "pre-op",
                },
            )
        self.assertEqual(resp.status_code, 302)
        m["custodian_sign_consent_request"].assert_called_once()
        self.assertTrue(
            ConsentRecord.objects.filter(
                request_id="1d1d1d1d-0000-4000-8000-000000000001"
            ).exists()
        )
        self.assertTrue(
            PatientNotification.objects.filter(
                patient_id="pat-101", kind=NotificationKind.CONSENT_REQUEST
            ).exists()
        )
