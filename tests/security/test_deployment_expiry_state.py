"""Timer state is mirrored only after its audit entry is committed."""

from unittest.mock import Mock

import pytest
from api import audit_client
from contracts.enums import LifecycleState


def test_expiry_state_follows_audit_and_refuses_failed_append(monkeypatch):
    operations = []
    append = Mock(side_effect=lambda *a, **kw: operations.append("audit"))
    write = Mock(side_effect=lambda *a: operations.append("store"))
    monkeypatch.setattr(audit_client, "append_entry", append)
    logger = audit_client.make_lifecycle_audit_logger(
        "http://audit", state_writer=write
    )
    entry = {
        "record_id": "rec-1",
        "to_state": "granted",
        "event_id": "event-1",
        "actor_id": "timer",
        "correlation_id": "expiry-1",
    }
    logger(entry)
    assert operations == ["audit", "store"]
    write.assert_called_once_with("rec-1", LifecycleState.GRANTED, "event-1")
    write.reset_mock()
    append.side_effect = audit_client.AuditServiceError("audit unavailable")
    with pytest.raises(audit_client.AuditServiceError):
        logger(entry)
    write.assert_not_called()


def test_store_write_failure_after_audit_is_logged_not_raised(monkeypatch, caplog):
    """A failed mirror write must not kill the expiry monitor (ADR-0047)."""
    append = Mock()
    monkeypatch.setattr(audit_client, "append_entry", append)
    write = Mock(side_effect=RuntimeError("store down"))
    logger = audit_client.make_lifecycle_audit_logger(
        "http://audit", state_writer=write
    )
    entry = {
        "record_id": "rec-1",
        "to_state": "granted",
        "event_id": "event-1",
        "actor_id": "timer",
        "correlation_id": "expiry-1",
    }
    with caplog.at_level("ERROR", logger="api.audit_client"):
        logger(entry)
    append.assert_called_once()
    write.assert_called_once()
    assert "store state not written for record rec-1" in caplog.text
