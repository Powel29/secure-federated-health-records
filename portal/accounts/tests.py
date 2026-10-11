"""Registration + the ADR-0021 invariant.

Run with the SQLite unit settings (no store needed)::

    python manage.py test --settings=config.test_settings
"""

from __future__ import annotations

from django.test import TestCase
from portal_core import stubs

from accounts.models import Profile, RegistrationRequest, RequestStatus


class RegistrationTests(TestCase):
    def test_patient_self_registration_creates_pending_request(self):
        resp = self.client.post(
            "/accounts/register/patient/",
            {"username": "alice", "password": "pw12345", "patient_id": "pat-101"},
        )
        self.assertEqual(resp.status_code, 302)
        # Review F17: the request records the id; no identity is bound yet.
        self.assertFalse(Profile.objects.filter(subject_id="pat-101").exists())
        req = RegistrationRequest.objects.get(subject_id="pat-101")
        self.assertEqual(req.status, RequestStatus.PENDING)
        self.assertIn("owner:pat-101", req.requested_attributes)

    def test_clinician_self_registration_creates_pending_request(self):
        resp = self.client.post(
            "/accounts/register/clinician/",
            {
                "username": "bob",
                "password": "pw12345",
                "clinician_id": "doc-201",
                "requested_attributes": "role:physician",
                "license_info": "lic-999",
            },
        )
        self.assertEqual(resp.status_code, 302)
        req = RegistrationRequest.objects.get(subject_id="doc-201")
        self.assertEqual(req.status, RequestStatus.PENDING)

    def test_invariant_signup_never_issues_a_credential(self):
        """The ADR-0021 invariant: a self-registered account gets no credential."""
        self.client.post(
            "/accounts/register/clinician/",
            {"username": "carol", "password": "pw12345", "clinician_id": "doc-301"},
        )
        # Nothing is ISSUED anywhere, and the issue path is not reachable from here.
        self.assertFalse(
            RegistrationRequest.objects.filter(status=RequestStatus.ISSUED).exists()
        )
        with self.assertRaises(stubs.NotWiredYet):
            stubs.issue_credential(RegistrationRequest.objects.first().id)

    def test_crypto_actions_fail_closed(self):
        with self.assertRaises(stubs.NotWiredYet):
            stubs.ingest_upload("pat-101", "scan.png", b"")
        with self.assertRaises(stubs.NotWiredYet):
            stubs.declare_breakglass("doc-201", "pat-101", "cardiac_arrest")
        with self.assertRaises(stubs.NotWiredYet):
            stubs.request_access("doc-201", "pat-101")



class SelfRegistrationCannotClaimAnIdentityTests(TestCase):
    """Review F17: signing up as ``doc-201`` does not make you doc-201."""

    def test_unissued_registration_cannot_reach_custodian(self):
        from unittest import mock

        from portal_core.testing import patched

        self.client.post(
            "/accounts/register/clinician/",
            {"username": "mallory", "password": "pw12345", "clinician_id": "doc-301"},
        )
        with patched(custodian_subject=mock.Mock()) as services:
            resp = self.client.get("/clinician/")
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/")
        services["custodian_subject"].assert_not_called()
        home = self.client.get("/")
        self.assertContains(home, "pending approval")

    def test_profile_with_pending_request_is_still_refused(self):
        """Even a bound profile waits until its credential is issued."""
        from portal_core.testing import clinician

        user = clinician(username="newdoc", subject_id="doc-777")
        RegistrationRequest.objects.create(
            user=user, role="clinician", subject_id="doc-777"
        )
        self.client.login(username="newdoc", password="pw12345")
        resp = self.client.get("/clinician/")
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/")

    def test_registering_existing_subject_id_rejected(self):
        from portal_core.testing import clinician

        clinician(username="house", subject_id="doc-201")
        resp = self.client.post(
            "/accounts/register/clinician/",
            {"username": "mallory", "password": "pw12345", "clinician_id": "doc-201"},
        )
        self.assertContains(resp, "already taken")
        self.assertFalse(
            RegistrationRequest.objects.filter(user__username="mallory").exists()
        )

    def test_signup_writes_no_patient_directory_row(self):
        from accounts.models import PatientDirectory

        self.client.post(
            "/accounts/register/patient/",
            {
                "username": "eve",
                "password": "pw12345",
                "patient_id": "pat-555",
                "given_name": "Eve",
                "family_name": "Mallory",
                "date_of_birth": "1990-01-01",
            },
        )
        self.assertFalse(PatientDirectory.objects.filter(subject_id="pat-555").exists())
