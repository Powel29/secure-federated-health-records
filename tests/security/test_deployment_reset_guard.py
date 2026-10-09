"""The destructive schema reset only ever reaches a local database (ADR-0047).

Claim: ``deploy.run_local``'s fresh-federation reset cannot drop the schema of
a remote store, however ``DATABASE_URL`` or ``PGHOST`` is set.
"""

import pytest

from deploy import bootstrap


class _Connected(Exception):
    """Raised by the fake connect: the guard let the reset through."""


@pytest.fixture
def connect_calls(monkeypatch):
    calls = []

    def fake_connect(dsn, *args, **kwargs):
        calls.append(dsn)
        raise _Connected

    monkeypatch.setattr(bootstrap.psycopg, "connect", fake_connect)
    monkeypatch.delenv("PGHOST", raising=False)
    monkeypatch.delenv("PGHOSTADDR", raising=False)
    return calls


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://postgres@127.0.0.1:55433/ehr",
        "postgresql://postgres@localhost/ehr",
        "host=/var/run/postgresql dbname=ehr",
        "dbname=ehr",
    ],
)
def test_reset_reaches_a_local_database(connect_calls, dsn):
    with pytest.raises(_Connected):
        bootstrap.run_migrations(dsn, reset=True)
    assert connect_calls == [dsn]


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://postgres@db.example.invalid:5432/ehr",
        "postgresql://postgres@10.0.0.5/ehr",
        "host=localhost,db.example.invalid dbname=ehr",
        "host=localhost hostaddr=10.0.0.5 dbname=ehr",
    ],
)
def test_reset_refuses_a_remote_database_before_connecting(connect_calls, dsn):
    with pytest.raises(bootstrap.BootstrapError, match="non-local host"):
        bootstrap.run_migrations(dsn, reset=True)
    assert connect_calls == []


def test_reset_refuses_a_remote_pghost_when_the_dsn_names_no_host(
    connect_calls, monkeypatch
):
    monkeypatch.setenv("PGHOST", "db.example.invalid")
    with pytest.raises(bootstrap.BootstrapError, match="non-local host"):
        bootstrap.run_migrations("dbname=ehr", reset=True)
    assert connect_calls == []


def test_migrations_without_reset_may_target_any_host(connect_calls):
    dsn = "postgresql://postgres@db.example.invalid/ehr"
    with pytest.raises(_Connected):
        bootstrap.run_migrations(dsn)
    assert connect_calls == [dsn]


def test_portal_schema_reset_refuses_a_remote_database_before_connecting(
    connect_calls,
):
    from deploy import run_portal_demo

    with pytest.raises(bootstrap.BootstrapError, match="non-local host"):
        run_portal_demo._prepare_portal_schema(
            "postgresql://u@db.example.com/ehr", reset=True
        )
    assert connect_calls == []
