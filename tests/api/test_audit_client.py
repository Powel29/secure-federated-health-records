"""Tests for the Audit Service HTTP client (P4-2, C14).

No Postgres needed: these tests fake the wire, not the audit service's own
logic (that belongs to ``tests/api/test_audit_service.py`` and the
already-tested ``audit.chain`` / ``audit.share_custody`` modules). Here we
only check that :mod:`api.audit_client` shapes requests and parses responses
correctly, and that a transport failure surfaces as ``AuditServiceError``
rather than being swallowed.
"""

from __future__ import annotations

import httpx
import pytest
from api import audit_client
from api.audit_client import (
    AuditServiceError,
    _tls_verify,
    append_entry,
    make_lifecycle_audit_logger,
)


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                "boom",
                request=httpx.Request("POST", "http://audit/entries"),
                response=None,
            )

    def json(self) -> dict:
        return self._payload


def test_append_entry_posts_expected_shape_and_returns_entry(monkeypatch):
    captured: dict = {}

    def fake_post(url, *, json, timeout, verify=True):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout
        captured["verify"] = verify
        return _FakeResponse(
            200, {"entry": {"seq": 1, "event_type": json["event_type"]}}
        )

    monkeypatch.setattr(httpx, "post", fake_post)

    entry = append_entry(
        "http://audit:8020",
        event_type="lifecycle_transition",
        event_data={"record_id": "rec-1"},
        actor_id="system:hsm-timer",
        correlation_id="corr-1",
    )

    assert captured["url"] == "http://audit:8020/entries"
    assert captured["json"] == {
        "event_type": "lifecycle_transition",
        "event_data": {"record_id": "rec-1"},
        "actor_id": "system:hsm-timer",
        "correlation_id": "corr-1",
    }
    assert entry == {"seq": 1, "event_type": "lifecycle_transition"}


def test_append_entry_raises_audit_service_error_on_transport_failure(monkeypatch):
    def fake_post(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", fake_post)

    with pytest.raises(AuditServiceError):
        append_entry(
            "http://audit:8020",
            event_type="lifecycle_transition",
            event_data={},
            actor_id="system:hsm-timer",
            correlation_id="corr-1",
        )


def test_append_entry_raises_on_non_2xx_status(monkeypatch):
    def fake_post(*args, **kwargs):
        return _FakeResponse(503, {"detail": "unavailable"})

    monkeypatch.setattr(httpx, "post", fake_post)

    with pytest.raises(AuditServiceError):
        append_entry(
            "http://audit:8020",
            event_type="lifecycle_transition",
            event_data={},
            actor_id="system:hsm-timer",
            correlation_id="corr-1",
        )


def test_tls_verify_is_on_by_default(monkeypatch):
    monkeypatch.delenv("TLS_VERIFY", raising=False)
    monkeypatch.delenv("CAPTURE_TLS", raising=False)
    assert _tls_verify() is True


def test_tls_verify_off_alone_does_not_disable(monkeypatch):
    """A lone TLS_VERIFY=false must NOT disable verification -- fail-open guard."""
    monkeypatch.setenv("TLS_VERIFY", "false")
    monkeypatch.delenv("CAPTURE_TLS", raising=False)
    assert _tls_verify() is True


def test_tls_verify_disabled_only_under_capture_double_gate(monkeypatch):
    """Both CAPTURE_TLS=true and TLS_VERIFY=false are required to disable."""
    monkeypatch.setenv("CAPTURE_TLS", "true")
    monkeypatch.setenv("TLS_VERIFY", "false")
    assert _tls_verify() is False

    # capture profile on, but verify not explicitly disabled -> still verifies
    monkeypatch.setenv("TLS_VERIFY", "true")
    assert _tls_verify() is True


def test_lifecycle_audit_logger_uses_entrys_own_actor_and_correlation(monkeypatch):
    captured: dict = {}

    def fake_post(url, *, json, timeout, verify=True):
        captured.update(json)
        return _FakeResponse(200, {"entry": {"seq": 1}})

    monkeypatch.setattr(httpx, "post", fake_post)

    logger = make_lifecycle_audit_logger("http://audit:8020")
    logger(
        {
            "event_id": "evt-1",
            "record_id": "rec-1",
            "from_state": "emergency_open",
            "to_state": "expired",
            "actor_id": "system:hsm-timer",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "correlation_id": "corr-9",
        }
    )

    assert captured["event_type"] == "lifecycle_transition"
    assert captured["actor_id"] == "system:hsm-timer"
    assert captured["correlation_id"] == "corr-9"
    assert captured["event_data"]["record_id"] == "rec-1"


@pytest.fixture(autouse=True)
def _fresh_seq_memory(monkeypatch):
    """Each test starts with no remembered chain position."""
    monkeypatch.setattr(audit_client, "_last_seq", {})


def test_append_refuses_a_chain_that_goes_backwards(monkeypatch):
    """Review F31: a lower seq than one already returned means the chain was
    truncated or replaced, so the caller is told the entry is not trustworthy."""
    seqs = iter([5, 6, 3])

    def fake_post(url, *, json, timeout, verify=True):
        return _FakeResponse(200, {"entry": {"seq": next(seqs)}})

    monkeypatch.setattr(httpx, "post", fake_post)
    kwargs = dict(event_type="t", event_data={}, actor_id="a", correlation_id="c")
    append_entry("http://audit:8020", **kwargs)
    append_entry("http://audit:8020", **kwargs)
    with pytest.raises(AuditServiceError, match="went backwards"):
        append_entry("http://audit:8020", **kwargs)
