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


class OverviewTests(TestCase):
    def test_overview_renders_with_chain_stats(self) -> None:
        admin()
        self.client.login(username="auditor", password="pw12345")
        with mock.patch("portal_core.store_reader.chain_stats", return_value={"head": None, "length": 3}), mock.patch(
            "portal_core.store_reader.recent_audit", return_value=[]
        ), mock.patch("portal_core.store_reader.event_type_counts", return_value=[]), patched(
            audit_verify=mock.Mock(return_value={"verified": True, "head_seq": 2})
        ):
            resp = self.client.get("/oversight/")
        self.assertContains(resp, "PASS")
        self.assertContains(resp, "Trace by correlation ID")


class CaseReviewTests(TestCase):
    def setUp(self) -> None:
        admin()
        self.client.login(username="auditor", password="pw12345")

    def test_chain_only_flow_without_a_portal_case_renders(self) -> None:
        """A break-glass in the chain with no ledger row must not 500 the page."""
        flow = {
            "correlation_id": "bg-chain-only", "first_seq": 5, "last_seq": 7, "entries": 3,
            "started_at": timezone.now(), "released": True, "expired": False,
        }
        with mock.patch("portal_core.store_reader.breakglass_correlations", return_value=[flow]):
            resp = self.client.get("/oversight/cases/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "chain only")

    def test_failed_case_without_a_chain_flow_renders(self) -> None:
        BreakglassCase.objects.create(
            correlation_id="bg-failed", record_id="rec-002", patient_id="pat-102", clinician_id="doc-201",
            facility_id="facility-b", reason_code="stroke", status=CaseStatus.FAILED,
            failure_reason="custodian: refused",
        )
        with mock.patch("portal_core.store_reader.breakglass_correlations", return_value=[]):
            resp = self.client.get("/oversight/cases/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "failed closed")


class HygieneTests(TestCase):
    """Review F42: bad input is a 400, and an unverifiable chain says so."""

    def setUp(self) -> None:
        admin()
        self.client.login(username="auditor", password="pw12345")

    def test_non_numeric_approve_is_400_not_500(self) -> None:
        resp = self.client.post("/oversight/registrations/", {"approve": "abc"})
        self.assertEqual(resp.status_code, 400)

    def test_links_intact_is_three_state(self) -> None:
        from admin_audit.views import _links_intact

        a = {"seq": 1, "entry_hash_hex": "aa", "prev_hash_hex": "00"}
        b = {"seq": 2, "entry_hash_hex": "bb", "prev_hash_hex": "aa"}
        gap = {"seq": 5, "entry_hash_hex": "ee", "prev_hash_hex": "dd"}
        broken = {"seq": 2, "entry_hash_hex": "bb", "prev_hash_hex": "zz"}
        self.assertIs(_links_intact([a, b]), True)
        self.assertIs(_links_intact([a, broken]), False)
        # No consecutive pair: nothing was checked, so it is not "intact".
        self.assertIsNone(_links_intact([a, gap]))
        self.assertIsNone(_links_intact([a]))
