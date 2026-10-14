"""Regression tests for care episodes, cross-record search and oversight."""

from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from accounts.models import PatientDirectory, PatientRepresentative
from ledger.models import BreakglassCase, CareEpisode, ConsentRecord, DowntimeEvent
from portal_core.clinical import digest
from portal_core.testing import (
    AuditLog,
    SUBJECT_CLINICIAN,
    admin,
    clinician,
    patched,
    refuse,
)


class ClinicalWorkflowTests(TestCase):
    def setUp(self) -> None:
        self.user = clinician()
        self.client.force_login(self.user)
        self.episode = CareEpisode.objects.create(
            patient_id="pat-101",
            clinician_id="doc-201",
            facility_id="facility-b",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.case = BreakglassCase.objects.create(
            correlation_id="original-case",
            record_id="rec-001",
            patient_id="pat-101",
            clinician_id="doc-201",
            facility_id="facility-a",
            reason_code="sepsis",
            justification="Urgent sepsis care needs allergy and medication history.",
            episode=self.episode,
            opened_at=timezone.now(),
            expires_at=self.episode.expires_at,
        )

    def _opened(self, subject: str, **kwargs: object) -> dict:
        return {
            "correlation_id": kwargs["correlation_id"],
            "facility_id": kwargs["facility_id"],
            "assertion_id": "test-assertion",
            "shares_presented": [
                {"holder": "audit-service", "x": 3, "audit_entry_seq": 11}
            ],
            "opened_at": timezone.now().isoformat(),
            "expires_at": self.episode.expires_at.isoformat(),
            "plaintext_b64": "SHOULD_NOT_BE_STORED",
        }

    def test_search_authorizes_each_general_record_and_reports_restricted_omissions(
        self,
    ) -> None:
        records = [
            {
                "record_id": rid,
                "facility_id": facility,
                "clinical": {"title": rid, "sensitivity": sensitivity},
            }
            for rid, facility, sensitivity in [
                ("rec-001", "facility-a", "general"),
                ("rec-002", "facility-b", "general"),
                ("restricted", "facility-a", "mental_health"),
            ]
        ]
        with (
            mock.patch("clinician.views._discover", return_value=records),
            patched(
                custodian_breakglass=mock.Mock(side_effect=self._opened),
                facility_emergency_search=mock.Mock(side_effect=lambda f, r, t, c: [r]),
            ) as services,
            mock.patch("portal_core.notify.notify_breakglass") as notice,
        ):
            response = self.client.post(
                f"/clinician/cases/{self.case.pk}/federated-search/",
                {"search_term": "Penicillin"},
            )
        self.assertContains(response, "Incomplete search")
        self.assertContains(response, "rec-002")
        self.assertEqual(services["custodian_breakglass"].call_count, 2)
        self.assertEqual(notice.call_count, 2)
        for call in services["custodian_breakglass"].call_args_list:
            self.assertLessEqual(call.kwargs["emergency_duration_seconds"], 3600)
            self.assertEqual(call.kwargs["patient_id"], self.case.patient_id)
        self.assertNotIn(
            "SHOULD_NOT_BE_STORED", str(list(BreakglassCase.objects.values()))
        )
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_search_outage_is_not_reported_as_a_complete_negative_result(self) -> None:
        with (
            mock.patch("clinician.views._discover", side_effect=refuse(503, "offline")),
            patched(custodian_breakglass=mock.Mock()) as services,
        ):
            response = self.client.post(
                f"/clinician/cases/{self.case.pk}/federated-search/",
                {"search_term": "penicillin"},
            )
        self.assertContains(response, "Incomplete search")
        services["custodian_breakglass"].assert_not_called()

    def test_closed_episode_cannot_authorize_more_searches(self) -> None:
        self.episode.closed_at = timezone.now()
        self.episode.save()
        with patched(custodian_breakglass=mock.Mock()) as services:
            response = self.client.post(
                f"/clinician/cases/{self.case.pk}/federated-search/",
                {"search_term": "penicillin"},
            )
        self.assertEqual(response.status_code, 403)
        services["custodian_breakglass"].assert_not_called()

    def test_other_clinician_cannot_use_the_case(self) -> None:
        self.client.force_login(clinician("other", "doc-other"))
        response = self.client.post(
            f"/clinician/cases/{self.case.pk}/federated-search/",
            {"search_term": "penicillin"},
        )
        self.assertEqual(response.status_code, 404)

    def test_temporary_encounter_has_no_historical_identity(self) -> None:
        response = self.client.post("/clinician/encounter/", {"action": "temporary"})
        self.assertContains(response, "No historical patient has been selected")
        episode = CareEpisode.objects.get(pk=self.client.session["clinician.episode"])
        self.assertEqual(episode.patient_id, "")
        self.assertTrue(episode.temporary_identifier.startswith("TEMP-"))
        self.assertNotIn("clinician.identified", self.client.session)

    def test_unidentified_encounter_cannot_be_resolved_when_audit_is_down(self) -> None:
        self.episode.patient_id = ""
        self.episode.save()
        session = self.client.session
        session["clinician.identified"] = {"patient_id": "pat-101"}
        session.save()
        with patched(audit_append=AuditLog(down=True)):
            response = self.client.post(
                "/clinician/encounter/",
                {
                    "action": "resolve",
                    "episode_id": str(self.episode.pk),
                    "evidence": "Two independent identifiers confirmed by registration staff.",
                },
            )
        self.assertContains(response, "Audit unavailable")
        self.episode.refresh_from_db()
        self.assertEqual(self.episode.patient_id, "")

    def test_episode_consent_groups_discovered_snapshot_and_rejects_forged_scope(
        self,
    ) -> None:
        records = [
            {
                "record_id": rid,
                "facility_id": "facility-a",
                "clinical": {"episode_id": "care-episode-1", "title": f"Report {rid}"},
            }
            for rid in ("rec-001", "rec-002")
        ]
        session = self.client.session
        session["clinician.discovery"] = {"pat-101": records}
        session.save()
        signed = {
            "request_id": "11111111-0000-4000-8000-000000000001",
            "scope": ["rec-001", "rec-002"],
            "requested_at": timezone.now().isoformat(),
            "expires_at": (timezone.now() + timedelta(days=1)).isoformat(),
        }
        with (
            patched(
                custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN),
                custodian_sign_consent_request=mock.Mock(return_value=signed),
            ) as services,
            mock.patch("portal_core.notify.notify_consent_request"),
        ):
            response = self.client.post(
                "/clinician/consent/",
                {
                    "patient_id": "pat-101",
                    "action": "request",
                    "episodes": ["care-episode-1"],
                    "purpose": "Current treating episode",
                },
            )
            self.assertEqual(response.status_code, 302)
            row = ConsentRecord.objects.get(request_id=signed["request_id"])
            self.assertEqual(row.scope, ["rec-001", "rec-002"])
            self.assertEqual(len(row.record_labels), 2)
            response = self.client.post(
                "/clinician/consent/",
                {
                    "patient_id": "pat-101",
                    "scope": ["another-patient-record"],
                    "purpose": "forged",
                },
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(services["custodian_sign_consent_request"].call_count, 1)

    def test_review_requires_integrity_and_audit_commit(self) -> None:
        self.client.force_login(admin())
        url = f"/admin-audit/cases/{self.case.pk}/review/"
        from django.urls import reverse

        url = reverse("admin_audit:review", args=[self.case.pk])
        data = {
            "outcome": "appropriate",
            "note": "Reviewed against the emergency care record and clinical need.",
        }
        with (
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=[]
            ),
            patched(audit_append=AuditLog(), audit_verify=mock.Mock(return_value={"verified": True})),
        ):
            response = self.client.post(url, data)
            self.assertContains(response, "does not match")
        committed = [
            {
                "event_data": {
                    "justification_digest": digest(self.case.justification),
                    "sensitive_justification_digest": digest(""),
                }
            }
        ]
        with (
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=committed
            ),
            patched(audit_append=AuditLog(down=True), audit_verify=mock.Mock(return_value={"verified": True})),
        ):
            response = self.client.post(url, data)
            self.assertContains(response, "remains pending")
        self.case.refresh_from_db()
        self.assertEqual(self.case.review_status, "pending")
        with (
            mock.patch(
                "portal_core.store_reader.audit_by_correlation", return_value=committed
            ),
            patched(audit_append=AuditLog(), audit_verify=mock.Mock(return_value={"verified": True})),
        ):
            self.assertEqual(self.client.post(url, data).status_code, 302)
        self.case.refresh_from_db()
        self.assertEqual(self.case.review_status, "appropriate")
        self.assertIsNotNone(self.case.review_audit_seq)

    def test_downtime_reconciliation_is_audited_and_idempotent(self) -> None:
        self.client.post("/clinician/downtime/", {"procedure": "local_downtime"})
        event = DowntimeEvent.objects.get()
        self.client.force_login(admin())
        from django.urls import reverse

        url = reverse("admin_audit:downtime")
        audit = AuditLog()
        with patched(audit_append=audit):
            self.client.post(url, {"event_id": str(event.pk)})
            self.client.post(url, {"event_id": str(event.pk)})
        self.assertEqual(len(audit.entries), 1)
        event.refresh_from_db()
        self.assertIsNotNone(event.reconciled_at)

    def test_representative_revocation_disables_notifications(self) -> None:
        patient = PatientDirectory.objects.create(
            subject_id="pat-101", given_name="Synthetic", family_name="Person"
        )
        representative = PatientRepresentative.objects.create(
            patient=patient,
            representative_id="rep-1",
            display_name="Synthetic Guardian",
            relationship="guardian",
            verification_reference="verified locally",
            verified_by="admin",
            expires_at=timezone.now() + timedelta(days=1),
            receive_notifications=True,
        )
        self.client.force_login(admin())
        from django.urls import reverse

        with patched(audit_append=AuditLog()):
            self.client.post(
                reverse("admin_audit:representatives"),
                {"action": "revoke", "representative_pk": representative.pk},
            )
        representative.refresh_from_db()
        self.assertIsNotNone(representative.revoked_at)
        self.assertFalse(representative.receive_notifications)
