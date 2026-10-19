"""A restarted facility still detects a truncated audit chain (review F31).

Backs the tamper-evidence claim across restarts: a facility remembers the
highest audit seq it has been given in a file on its own disk, so an audit
service whose chain was cut back while the facility was down is refused
after the restart too, not trusted again from the next entry.
"""

from __future__ import annotations

import json

import httpx
import pytest
from api import audit_client
from api.audit_client import AuditServiceError, append_entry, use_high_water_file

AUDIT_URL = "http://audit:8020"
AUTH = httpx.Auth()
KWARGS = dict(event_type="t", event_data={}, actor_id="a", correlation_id="c")


class _Answer:
    def __init__(self, seq: int) -> None:
        self._seq = seq

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"entry": {"seq": self._seq}}


@pytest.fixture(autouse=True)
def _fresh_process(monkeypatch):
    """Each test starts as a newly started process: no mark, no file."""
    monkeypatch.setattr(audit_client, "_last_seq", {})
    monkeypatch.setattr(audit_client, "_high_water_file", None)


def _audit_answers(monkeypatch, *seqs: int) -> None:
    answers = iter(seqs)
    monkeypatch.setattr(httpx, "post", lambda url, **_: _Answer(next(answers)))


def _restart() -> None:
    """Drop everything the process held in memory, as a restart does."""
    audit_client._last_seq = {}
    audit_client._high_water_file = None


def test_truncated_chain_refused_after_facility_restart(tmp_path, monkeypatch):
    mark = tmp_path / "audit-high-water.json"
    use_high_water_file(mark)
    _audit_answers(monkeypatch, 41, 42)
    append_entry(AUDIT_URL, auth=AUTH, **KWARGS)
    append_entry(AUDIT_URL, auth=AUTH, **KWARGS)

    _restart()
    use_high_water_file(mark)
    # The chain was cut back to seq 6 while the facility was down.
    _audit_answers(monkeypatch, 7)
    with pytest.raises(AuditServiceError, match="went backwards"):
        append_entry(AUDIT_URL, auth=AUTH, **KWARGS)
    assert json.loads(mark.read_text(encoding="utf-8")) == {AUDIT_URL: 42}


def test_chain_that_keeps_growing_is_accepted_after_restart(tmp_path, monkeypatch):
    """Setup check for the test above: the restart alone refuses nothing."""
    mark = tmp_path / "audit-high-water.json"
    use_high_water_file(mark)
    _audit_answers(monkeypatch, 42)
    append_entry(AUDIT_URL, auth=AUTH, **KWARGS)

    _restart()
    use_high_water_file(mark)
    _audit_answers(monkeypatch, 43)
    assert append_entry(AUDIT_URL, auth=AUTH, **KWARGS)["seq"] == 43
    assert json.loads(mark.read_text(encoding="utf-8")) == {AUDIT_URL: 43}


@pytest.mark.parametrize(
    "content",
    ["not json", "[1, 2]", json.dumps({AUDIT_URL: "42"}), json.dumps({AUDIT_URL: 4.2})],
)
def test_unreadable_high_water_file_stops_startup(tmp_path, content):
    """A mark the facility cannot read is not silently treated as no mark."""
    mark = tmp_path / "audit-high-water.json"
    mark.write_text(content, encoding="utf-8")
    with pytest.raises(RuntimeError, match="audit high-water file"):
        use_high_water_file(mark)
    assert audit_client._high_water_file is None
    assert audit_client._last_seq == {}


def test_entry_refused_when_the_mark_cannot_be_saved(tmp_path, monkeypatch):
    """An entry is not accepted unless its mark is on disk first."""
    use_high_water_file(tmp_path / "missing-dir" / "audit-high-water.json")
    _audit_answers(monkeypatch, 1)
    with pytest.raises(AuditServiceError, match="could not persist"):
        append_entry(AUDIT_URL, auth=AUTH, **KWARGS)


def test_facility_refuses_to_start_without_a_high_water_file(monkeypatch):
    from deploy.asgi import facility

    monkeypatch.setenv("FACILITY_ID", "facility-a")
    monkeypatch.setenv("DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("AUDIT_SERVICE_URL", AUDIT_URL)
    monkeypatch.delenv("AUDIT_HIGH_WATER_FILE", raising=False)
    with pytest.raises(RuntimeError, match="AUDIT_HIGH_WATER_FILE"):
        facility.app()
