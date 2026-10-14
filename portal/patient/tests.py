"""Patient portal tests (P4-7, P4-10) -- SQLite settings, services mocked.

Run with::

    python manage.py test --settings=config.test_settings
"""

from __future__ import annotations

import base64
from datetime import date, timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from accounts.models import PatientDirectory, PatientRepresentative
from ledger.models import (
    ConsentRecord,
    ConsentStatus,
    NotificationKind,
    PatientNotification,
)
from portal_core.testing import (
    TEST_PASSWORD,
    RECORD_META,
    SIGNED_REQUEST,
    SUBJECT_CLINICIAN,
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
        self.client.login(username="alice", password=TEST_PASSWORD)

    def test_owner_read_streams_plaintext_for_this_request_only(self) -> None:
        payload = base64.b64encode(b'{"diagnosis": "AMI"}').decode()
        with (
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
            patched(
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
            ) as m,
        ):
            resp = self.client.post("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "AMI")
        self.assertEqual(resp["Cache-Control"], "no-store")
        m["custodian_read"].assert_called_once()
        self.assertEqual(
            m["custodian_read"].call_args.kwargs["facility_id"], "facility-a"
        )
        # A GET afterwards shows nothing decrypted: nothing was persisted.
        with (
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
            patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)),
        ):
            again = self.client.get("/patient/records/rec-001/")
        self.assertNotContains(again, "AMI")

    def test_login_without_owner_attribute_decrypts_nothing(self) -> None:
        """ADR-0016 / P5-1: the policy refusal is shown; no plaintext, no 500."""
        with (
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
            patched(
                custodian_read=mock.Mock(
                    side_effect=refuse(403, "record read: Policy denied: no path")
                ),
                custodian_subject=mock.Mock(return_value=None),
            ),
        ):
            resp = self.client.post("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "access is not granted by keys", status_code=403)
        self.assertContains(resp, "Policy denied", status_code=403)
        self.assertNotContains(resp, "plaintext_b64", status_code=403)

    def test_login_with_no_key_agent_material_is_refused(self) -> None:
        """ADR-0021: a portal account alone grants zero access."""
        with (
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
            patched(
                custodian_read=mock.Mock(
                    side_effect=refuse(
                        404, "no key material held for subject 'pat-101'"
                    )
                ),
                custodian_subject=mock.Mock(return_value=None),
            ),
        ):
            resp = self.client.post("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "no key material", status_code=403)

    def test_another_patients_record_is_not_revealed(self) -> None:
        other = dict(RECORD_META, patient_id="pat-999")
        with mock.patch("portal_core.store_reader.record_meta", return_value=other):
            self.assertEqual(
                self.client.get("/patient/records/rec-001/").status_code, 404
            )
            self.assertEqual(
                self.client.post("/patient/records/rec-001/").status_code, 404
            )

    def test_store_outage_is_an_explicit_error_not_a_blank_page(self) -> None:
        with mock.patch(
            "portal_core.store_reader.record_meta", side_effect=RuntimeError("db down")
        ):
            resp = self.client.get("/patient/records/rec-001/")
        self.assertEqual(resp.status_code, 503)
        self.assertContains(resp, "Store unreachable", status_code=503)


class PatientConsentTests(TestCase):
    """Page 2: approve / deny / revoke sign through the custodian, verify at the facility."""

    def setUp(self) -> None:
        self.user = patient()
        clinician()
        self.client.login(username="alice", password=TEST_PASSWORD)
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
                return_value={
                    "grant": signed_grant("granted"),
                    "patient_certificate_pem": "PEM",
                }
            ),
            facility_submit_grant=mock.Mock(return_value={"status": "accepted"}),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ) as m:
            resp = self.client.post(
                f"/patient/access/{self.row.request_id}/decide/",
                {"decision": "granted"},
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
                return_value={
                    "grant": signed_grant("granted"),
                    "patient_certificate_pem": "PEM",
                }
            ),
            facility_submit_grant=mock.Mock(
                side_effect=refuse(
                    400, "Consent grant signature verification failed", "facility"
                )
            ),
            audit_append=AuditLog(),
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ):
            self.client.post(
                f"/patient/access/{self.row.request_id}/decide/",
                {"decision": "granted"},
            )
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
                return_value={
                    "grant": signed_grant("revoked"),
                    "patient_certificate_pem": "PEM",
                }
            ),
            facility_submit_grant=mock.Mock(return_value={"status": "revoked"}),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ):
            resp = self.client.post(f"/patient/access/{self.row.request_id}/revoke/")
        self.assertEqual(resp.status_code, 302)
        self.row.refresh_from_db()
        self.assertEqual(self.row.status, ConsentStatus.REVOKED)
        note = PatientNotification.objects.get(
            patient_id="pat-101", kind=NotificationKind.REVOKED
        )
        self.assertEqual(note.correlation_id, "consent-abc")
        self.assertIsNotNone(note.audit_seq)
        chain = audit.of_type("patient.notification")
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0]["event_data"]["kind"], "revoked")
        # Surfaced on the patient's home page.
        with (
            patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)),
            mock.patch("portal_core.store_reader.records_for_patient", return_value=[]),
        ):
            home = self.client.get("/patient/")
        self.assertContains(home, "was revoked")

    def test_only_a_live_grant_can_be_revoked(self) -> None:
        with patched(custodian_revoke_consent=mock.Mock()) as m:
            self.client.post(f"/patient/access/{self.row.request_id}/revoke/")
        m["custodian_revoke_consent"].assert_not_called()


class GuardianConsentTests(TestCase):
    """ADR-0061: a verified guardian or parent decides consent for a minor only."""

    def setUp(self) -> None:
        patient("parent", "pat-900")
        clinician()
        self.client.login(username="parent", password=TEST_PASSWORD)
        self.minor = PatientDirectory.objects.create(
            subject_id="pat-150",
            given_name="Synthetic",
            family_name="Child",
            date_of_birth=date.today() - timedelta(days=10 * 365),
        )
        self.link = PatientRepresentative.objects.create(
            patient=self.minor,
            representative_id="pat-900",
            display_name="Synthetic Parent",
            relationship="parent",
            verification_reference="birth certificate checked",
            verified_by="admin-auditor",
            expires_at=timezone.now() + timedelta(days=30),
        )
        self.row = ConsentRecord.objects.create(
            request_id=SIGNED_REQUEST["request_id"],
            patient_id="pat-150",
            requester_id="doc-201",
            requester_facility_id="facility-b",
            scope=["rec-150"],
            purpose="paediatric follow-up",
            requested_at=timezone.now(),
            request_expires_at=timezone.now() + timedelta(days=7),
            request_json=SIGNED_REQUEST,
            correlation_id="consent-minor",
        )

    def _decide(self) -> tuple[object, dict]:
        audit = AuditLog()
        with patched(
            custodian_decide_consent=mock.Mock(
                return_value={
                    "grant": signed_grant("granted"),
                    "patient_certificate_pem": "PEM",
                }
            ),
            facility_submit_grant=mock.Mock(return_value={"status": "accepted"}),
            audit_append=audit,
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ) as m:
            resp = self.client.post(
                f"/patient/access/{self.row.request_id}/decide/",
                {"decision": "granted", "for": "pat-150"},
            )
        return resp, {"audit": audit, **m}

    def test_parent_sees_the_minors_pending_request(self) -> None:
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)):
            resp = self.client.get("/patient/access/?for=pat-150")
        self.assertContains(resp, "paediatric follow-up")
        self.assertContains(resp, "Deciding as the verified guardian")
        self.assertContains(resp, 'name="for" value="pat-150"')

    def test_parent_signs_as_the_minor_and_is_logged_as_decider(self) -> None:
        resp, m = self._decide()
        self.assertRedirects(
            resp, "/patient/access/?for=pat-150", fetch_redirect_response=False
        )
        m["custodian_decide_consent"].assert_called_once_with(
            "pat-150", request=SIGNED_REQUEST, status="granted", ttl_days=5
        )
        event = m["audit"].of_type("consent.decision")[0]["event_data"]
        self.assertEqual(event["patient_id"], "pat-150")
        self.assertEqual(event["decided_by"], "pat-900")

    def test_no_authority_without_a_live_guardian_link_to_a_minor(self) -> None:
        cases = {
            "next of kin": {"relationship": "next_of_kin"},
            "revoked": {"revoked_at": timezone.now()},
            "expired": {"expires_at": timezone.now() - timedelta(minutes=1)},
        }
        for label, change in cases.items():
            with self.subTest(label):
                PatientRepresentative.objects.filter(pk=self.link.pk).update(**change)
                resp, m = self._decide()
                self.assertEqual(resp.status_code, 404)
                m["custodian_decide_consent"].assert_not_called()
                PatientRepresentative.objects.filter(pk=self.link.pk).update(
                    relationship="parent",
                    revoked_at=None,
                    expires_at=timezone.now() + timedelta(days=30),
                )
        with self.subTest("adult"):
            self.minor.date_of_birth = date(1990, 1, 1)
            self.minor.save()
            resp, m = self._decide()
            self.assertEqual(resp.status_code, 404)
            m["custodian_decide_consent"].assert_not_called()


class ProfileTests(TestCase):
    """Each role sees its own details, read only, from its own login."""

    def test_patient_sees_own_directory_credentials_and_guardians(self) -> None:
        patient()
        self.client.login(username="alice", password=TEST_PASSWORD)
        own = PatientDirectory.objects.create(
            subject_id="pat-101",
            given_name="Alice",
            family_name="Vance",
            date_of_birth=date(1982, 4, 15),
            aliases=["Ali Vance"],
        )
        PatientDirectory.objects.create(
            subject_id="pat-777", given_name="Other", family_name="Person"
        )
        PatientRepresentative.objects.create(
            patient=own,
            representative_id="pat-900",
            display_name="Synthetic Sibling",
            relationship="next_of_kin",
            verification_reference="checked",
            verified_by="admin-auditor",
            expires_at=timezone.now() + timedelta(days=30),
        )
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)):
            resp = self.client.get("/patient/profile/")
        self.assertContains(resp, "<title>Your profile ·")
        self.assertContains(resp, "1982-04-15")
        self.assertContains(resp, "Ali Vance")
        self.assertContains(resp, "owner:pat-101")
        self.assertContains(resp, "Synthetic Sibling")
        self.assertContains(resp, 'href="/patient/profile/"')
        self.assertNotContains(resp, "pat-777")
        self.assertContains(resp, "Key agent enrolled")
        self.assertNotContains(resp, "No certificate")

    def test_clinician_sees_own_credentials_and_facility(self) -> None:
        from accounts.models import Role
        from portal_core.testing import make_user

        make_user("rao", Role.CLINICIAN, "doc-201", "facility-b")
        self.client.login(username="rao", password=TEST_PASSWORD)
        with patched(custodian_subject=mock.Mock(return_value=SUBJECT_CLINICIAN)):
            resp = self.client.get("/clinician/profile/")
        self.assertContains(resp, "Dr. Arjun Rao")
        self.assertContains(resp, "role:emergency-physician")
        self.assertContains(resp, "Certificate chains to root")
        self.assertContains(resp, "facility-b")
        self.assertNotContains(resp, "Identification details")

    def test_profiles_follow_the_role(self) -> None:
        patient()
        self.client.login(username="alice", password=TEST_PASSWORD)
        self.assertEqual(self.client.get("/clinician/profile/").status_code, 302)


class PatientHistoryAndRoleTests(TestCase):
    def test_break_glass_rows_are_badged(self) -> None:
        patient()
        self.client.login(username="alice", password=TEST_PASSWORD)
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
                "event_data": {
                    "record_id": "rec-001",
                    "requester_id": "doc-301",
                    "denied_by": "policy",
                },
                "actor_id": "facility-a",
                "correlation_id": "c2",
                "recorded_at": timezone.now(),
                "entry_hash_hex": "abcdef0124",
                "prev_hash_hex": "abcdef0123",
            },
        ]
        with (
            mock.patch(
                "portal_core.store_reader.records_for_patient",
                return_value=[RECORD_META],
            ),
            mock.patch(
                "portal_core.store_reader.audit_for_patient", return_value=entries
            ),
            patched(custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT)),
        ):
            resp = self.client.get("/patient/history/?type=breakglass")
        self.assertContains(resp, "break-glass")
        self.assertNotContains(resp, "doc-301")

    def test_patient_is_routed_away_from_clinician_pages(self) -> None:
        patient()
        self.client.login(username="alice", password=TEST_PASSWORD)
        resp = self.client.get("/clinician/identify/")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].startswith("/patient/"))


class PatientUploadTests(TestCase):
    """Upload: bytes pass through once; the custodian seals at the facility."""

    def setUp(self) -> None:
        patient()
        self.client.login(username="alice", password=TEST_PASSWORD)

    def _post(self, **extra):
        from django.core.files.uploadedfile import SimpleUploadedFile

        data = {
            "file": SimpleUploadedFile(
                "echo.txt", b"EF 35%", content_type="text/plain"
            ),
            "facility_id": "facility-a",
            "preset": "cardiology",
            "search_terms": "echo, ef",
        }
        data.update(extra)
        return self.client.post("/patient/records/upload/", data)

    def test_upload_hands_bytes_and_policy_to_the_custodian(self) -> None:
        with patched(
            custodian_ingest=mock.Mock(
                return_value={
                    "record_id": "rec-abc",
                    "policy_id": "pol-1",
                    "search_terms_indexed": 2,
                }
            ),
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ) as m:
            resp = self._post()
        self.assertEqual(resp.status_code, 302)
        kwargs = m["custodian_ingest"].call_args.kwargs
        self.assertEqual(m["custodian_ingest"].call_args.args[0], "pat-101")
        self.assertEqual(kwargs["content"], b"EF 35%")
        self.assertEqual(kwargs["content_type"], "text/plain")
        self.assertEqual(kwargs["search_terms"], ["echo", "ef"])
        self.assertEqual(kwargs["clinical_policy"]["node_type"], "and")
        leaves = {
            (c["attribute"]["name"], c["attribute"]["value"])
            for c in kwargs["clinical_policy"]["children"]
        }
        self.assertEqual(leaves, {("role", "physician"), ("specialty", "cardiology")})

    def test_refusal_is_shown_and_nothing_is_stored_by_the_portal(self) -> None:
        with patched(
            custodian_ingest=mock.Mock(
                side_effect=refuse(403, "holds no owner credential")
            ),
            custodian_subject=mock.Mock(return_value=None),
        ):
            resp = self._post()
        self.assertEqual(resp.status_code, 403)
        self.assertContains(resp, "owner credential", status_code=403)

    def test_unknown_preset_or_facility_never_reaches_the_custodian(self) -> None:
        with patched(
            custodian_ingest=mock.Mock(),
            custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
        ) as m:
            self.assertEqual(self._post(preset="anything-goes").status_code, 400)
            self.assertEqual(self._post(facility_id="facility-z").status_code, 400)
        m["custodian_ingest"].assert_not_called()


class PortalHygieneTests(TestCase):
    """Review F42: redirects stay on this site; uploads never render as HTML."""

    def setUp(self) -> None:
        self.user = patient()
        self.client.login(username="alice", password=TEST_PASSWORD)

    def _note(self) -> PatientNotification:
        return PatientNotification.objects.create(
            patient_id="pat-101", kind=NotificationKind.REVOKED, title="t"
        )

    def test_mark_read_never_redirects_off_site(self) -> None:
        resp = self.client.post(
            f"/patient/notifications/{self._note().pk}/read/",
            {"next": "https://evil.example/phish"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertNotIn("evil.example", resp["Location"])

    def test_mark_read_follows_a_local_next(self) -> None:
        resp = self.client.post(
            f"/patient/notifications/{self._note().pk}/read/",
            {"next": "/patient/records/"},
        )
        self.assertEqual(resp["Location"], "/patient/records/")

    def _raw(self, content_type: str):
        payload = base64.b64encode(b"<script>alert(1)</script>").decode()
        with (
            mock.patch(
                "portal_core.store_reader.record_meta", return_value=RECORD_META
            ),
            patched(
                custodian_read=mock.Mock(
                    return_value={
                        "plaintext_b64": payload,
                        "content_type": content_type,
                    }
                ),
                custodian_subject=mock.Mock(return_value=SUBJECT_PATIENT),
            ),
        ):
            return self.client.post("/patient/records/rec-001/", {"mode": "raw"})

    def test_uploaded_html_downloads_with_nosniff(self) -> None:
        resp = self._raw("text/html")
        self.assertTrue(resp["Content-Disposition"].startswith("attachment"))
        self.assertEqual(resp["X-Content-Type-Options"], "nosniff")

    def test_uploaded_pdf_still_shows_inline(self) -> None:
        resp = self._raw("application/pdf")
        self.assertTrue(resp["Content-Disposition"].startswith("inline"))
        self.assertEqual(resp["X-Content-Type-Options"], "nosniff")
