"""A partial bootstrap or a restarted key service must never report success."""

from unittest.mock import MagicMock

import pytest

from deploy import compose_bootstrap as module


@pytest.fixture
def setup_bootstrap(monkeypatch):
    for name in (
        "DATABASE_URL",
        "AUDIT_SERVICE_URL",
        "CUSTODIAN_URL",
        "AUTHORITY_MED_URL",
        "AUTHORITY_NET_URL",
        "FACILITY_A_URL",
        "FACILITY_B_URL",
    ):
        monkeypatch.setenv(name, "test-local")
    monkeypatch.setenv("TLS_ENABLED", "false")
    monkeypatch.setenv("SEED_DATA", "true")
    connection = MagicMock()
    monkeypatch.setattr(module.psycopg, "connect", lambda _: connection)
    monkeypatch.setattr(module.bootstrap, "run_migrations", lambda _: [])
    monkeypatch.setattr(module, "service_instances", lambda _: {"audit": "current"})
    audit = MagicMock(return_value=0)
    seed = MagicMock()
    monkeypatch.setattr(module.bootstrap, "check_audit_chain", audit)
    monkeypatch.setattr(module.bootstrap, "seed_federation", seed)
    return connection.__enter__.return_value, audit, seed


def test_completed_bootstrap_rechecks_audit_chain(setup_bootstrap):
    conn, audit, seed = setup_bootstrap
    conn.execute.return_value.fetchone.side_effect = [
        ({"audit": "current"}, True),
        (2,),
    ]
    assert module.main() == 0
    audit.assert_called_once()
    seed.assert_not_called()


@pytest.mark.parametrize("completed", [None, ({"audit": "old-process"}, True)])
def test_partial_or_restarted_federation_is_refused(setup_bootstrap, completed):
    conn, audit, seed = setup_bootstrap
    conn.execute.return_value.fetchone.side_effect = [completed, (2,)]
    assert module.main() == 1
    audit.assert_not_called()
    seed.assert_not_called()


def test_audit_failure_on_retry_is_not_success(setup_bootstrap):
    conn, audit, seed = setup_bootstrap
    conn.execute.return_value.fetchone.side_effect = [
        ({"audit": "current"}, True),
        (2,),
    ]
    audit.side_effect = module.bootstrap.BootstrapError("tampered chain")
    assert module.main() == 1
    seed.assert_not_called()
