"""Admin / audit portal tests (P4-9) -- read-only, services mocked."""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from accounts.models import RegistrationRequest, RequestStatus, Role
from ledger.models import BreakglassCase, CaseStatus
from portal_core.services import ServiceStatus
from portal_core.testing import admin, patched

ENTRIES = [
    {"seq": 10, "event_type": "patient.lookup", "event_data": {"candidate_count": 2, "selected_patient_id": "pat-101"},
     "actor_id": "portal:clinician", "correlation_id": "lookup-1", "recorded_at": timezone.now(),
     "entry_hash_hex": "7f2a91aaaa", "prev_hash_hex": "0000"},
    {"seq": 11, "event_type": "breakglass_share_released", "event_data": {"record_id": "rec-001", "assertion_id": "9f2a"},
     "actor_id": "audit-service", "correlation_id": "lookup-1", "recorded_at": timezone.now(),
     "entry_hash_hex": "8b1c73bbbb", "prev_hash_hex": "7f2a91aaaa"},
    {"seq": 12, "event_type": "federation.rewrap", "event_data": {"record_id": "rec-001", "target_actor_id": "doc-201"},
     "actor_id": "facility-b", "correlation_id": "lookup-1", "recorded_at": timezone.now(),
     "entry_hash_hex": "d0947fcccc", "prev_hash_hex": "8b1c73bbbb"},
]


class TraceTests(TestCase):
    def setUp(self) -> None:
        admin()
        self.client.login(username="auditor", password="pw12345")

    def test_trace_by_correlation_id_shows_the_whole_flow(self) -> None:
        BreakglassCase.objects.create(
            correlation_id="lookup-1", record_id="rec-001", patient_id="pat-101", clinician_id="doc-201",
            facility_id="facility-b", reason_code="stroke", status=CaseStatus.OPEN,
            opened_at=timezone.now(), expires_at=timezone.now() + timedelta(minutes=2),
            shares=[{"holder": "clinician", "x": 1}, {"holder": "audit-service", "x": 3, "audit_entry_seq": 11}],
        )
        with mock.patch("portal_core.store_reader.audit_by_correlation", return_value=list(ENTRIES)), mock.patch(
            "portal_core.store_reader.chain_stats", return_value={"head": None, "length": 12}
        ), mock.patch("portal_core.store_reader.breakglass_correlations", return_value=[]), patched(
            audit_verify=mock.Mock(return_value={"verified": True, "head_seq": 12})
        ):
            resp = self.client.get("/oversight/trace/?cid=lookup-1")
        self.assertContains(resp, "patient.lookup")
        self.assertContains(resp, "breakglass_share_released")
        self.assertContains(resp, "federation.rewrap")
        self.assertContains(resp, "links intact")
        self.assertContains(resp, "PASS")
        self.assertContains(resp, "BG-0001")

    def test_broken_link_is_flagged(self) -> None:
        broken = [dict(e) for e in ENTRIES]
        broken[2]["prev_hash_hex"] = "deadbeef"
        with mock.patch("portal_core.store_reader.audit_by_correlation", return_value=broken), mock.patch(
            "portal_core.store_reader.chain_stats", return_value={"head": None, "length": 12}
        ), mock.patch("portal_core.store_reader.breakglass_correlations", return_value=[]), patched(
            audit_verify=mock.Mock(return_value={"verified": False, "head_seq": None})
        ):
            resp = self.client.get("/oversight/trace/?cid=lookup-1")
        self.assertContains(resp, "LINK BROKEN")
        self.assertContains(resp, "FAIL")

    def test_federation_page_reports_process_health(self) -> None:
        with patched(
            federation_status=mock.Mock(
                return_value=[
                    ServiceStatus("audit", "http://audit", True, "chain_head_seq=12"),
                    ServiceStatus("custodian", "http://custodian", False, "service unreachable"),
                ]
            )
        ), mock.patch("portal_core.store_reader.table_counts", return_value={"records": 3}), mock.patch(
            "portal_core.store_reader.facilities", return_value=[]
        ), mock.patch("portal_core.store_reader.authorities", return_value=[]), mock.patch(
            "portal_core.store_reader.record_summaries", return_value=[]
        ), mock.patch("portal_core.store_reader.lifecycle_states", return_value=[]):
            resp = self.client.get("/oversight/federation/")
        self.assertContains(resp, "chain_head_seq=12")
        self.assertContains(resp, "down")

    def test_portal_is_read_only_approval_reaches_only_the_stub(self) -> None:
        req = RegistrationRequest.objects.create(
            user=admin("second"), role=Role.CLINICIAN, subject_id="doc-999", status=RequestStatus.PENDING
        )
        resp = self.client.post("/oversight/registrations/", {"approve": req.pk})
        self.assertContains(resp, "never issues an attribute itself")
        req.refresh_from_db()
        self.assertEqual(req.status, RequestStatus.PENDING)
