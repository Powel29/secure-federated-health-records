"""Registration + the ADR-0021 invariant.

Run with the SQLite unit settings (no store needed)::

    python manage.py test --settings=config.test_settings
"""

from __future__ import annotations

from django.test import TestCase

from accounts.models import Profile, RegistrationRequest, RequestStatus
from portal_core import stubs


class RegistrationTests(TestCase):
    def test_patient_self_registration_creates_pending_request(self):
        resp = self.client.post(
            "/accounts/register/patient/",
            {"username": "alice", "password": "pw12345", "patient_id": "pat-101"},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(Profile.objects.filter(subject_id="pat-101").exists())
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
