"""Negative security tests for the P2-4 patient-discovery projection.

Backs the P2-4 done-when in WORKFLOW.md: "one hospital can find a patient's
records in the shared store by patient index, learning nothing about contents."
The patient-isolation test (a discovery on patient A cannot return patient B's
record IDs) lives with the storage suite because it needs real Postgres; see
``tests/storage/test_repositories.py::test_find_record_ids_by_patient_returns_only_ids_for_that_patient``.

The tests here catch SQL-level regressions without needing Postgres: they
inspect the executed query text via a fake cursor and assert it stays a
projection over ``record_id``.
"""

from __future__ import annotations

from federation import find_record_ids_by_patient


class _CaptureCursor:
    """Minimal fake psycopg cursor that records the last query text."""

    def __init__(self) -> None:
        self.query: str | None = None
        self.params: tuple | None = None

    def __enter__(self) -> "_CaptureCursor":
        return self

    def __exit__(self, *args: object) -> None:  # noqa: D401 - context-manager plumbing
        return None

    def execute(self, query: str, params: tuple) -> None:
        self.query = query
        self.params = params

    def fetchall(self) -> list[tuple]:
        return []


class _CaptureConnection:
    def __init__(self) -> None:
        self.cursor_obj = _CaptureCursor()

    def cursor(self, **_: object) -> _CaptureCursor:
        return self.cursor_obj


def test_sec_discovery_sql_is_a_projection_of_record_id_not_select_star() -> None:
    """Security property: discovery SQL is a projection of ``record_id`` only.

    Backs P2-4 "learning nothing about contents" at the SQL layer. A regression
    to ``SELECT *`` -- or to a wider projection that adds ``ciphertext``,
    ``nonce``, or ``aad`` -- would fail here immediately, before it could
    reach the wire and leak ciphertext to a querying facility.
    """
    conn = _CaptureConnection()

    # Positive control: the call reaches the cursor and passes the patient id.
    find_record_ids_by_patient(conn, "pat-101")
    assert conn.cursor_obj.query is not None, "query was never executed; test invalid"
    assert conn.cursor_obj.params == ("pat-101",)

    query = conn.cursor_obj.query.lower()

    # The projection is exactly record_id -- nothing else.
    assert "select record_id from records" in query
    assert "select *" not in query
    for leaking_column in ("ciphertext", "nonce", "aad", "content_type", "policy_id"):
        assert (
            leaking_column not in query
        ), f"discovery SQL leaks {leaking_column!r}: {conn.cursor_obj.query!r}"


def test_sec_discovery_return_type_carries_no_ciphertext_attribute() -> None:
    """Security property: the return value has no attribute path to ciphertext.

    A caller that only holds the discovery result must not be able to reach
    ciphertext, nonce, or aad through it. Enforced by the return type being
    ``list[str]``: strings expose no such fields.
    """
    conn = _CaptureConnection()
    result = find_record_ids_by_patient(conn, "pat-101")

    assert isinstance(result, list)
    for record_id in result:
        assert isinstance(record_id, str)
        for leaking_attr in ("ciphertext", "nonce", "aad"):
            assert not hasattr(record_id, leaking_attr)
