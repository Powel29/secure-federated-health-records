from storage.repositories import find_records_by_patient


class FakeCursor:
    def __init__(self):
        self.query = None
        self.params = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, query, params):
        self.query = query
        self.params = params

    def fetchall(self):
        return [
            {"record_id": "rec-1", "patient_id": "pat-123"},
            {"record_id": "rec-2", "patient_id": "pat-123"},
        ]


class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()

    def cursor(self, **kwargs):
        return self.cursor_obj


def test_find_records_by_patient(monkeypatch):
    conn = FakeConnection()

    monkeypatch.setattr(
        "storage.repositories.Record",
        lambda **row: row,
    )

    records = find_records_by_patient(conn, "pat-123")

    assert len(records) == 2
    assert records[0]["record_id"] == "rec-1"
    assert records[1]["record_id"] == "rec-2"
    assert conn.cursor_obj.params == ("pat-123",)
    assert "WHERE patient_id = %s" in conn.cursor_obj.query