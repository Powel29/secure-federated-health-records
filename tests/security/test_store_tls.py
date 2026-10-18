"""The TLS profile never talks to the store in the clear (ADR-0071).

P5-3 measured that the facility-store link carried every search token and
row count in plaintext even in the TLS profile. The control is
``sslmode=verify-full``, set for every connection by
``deploy.config.configure_transport``. This test runs it against the
suite's own Postgres, which serves no TLS (or, on a developer machine, a
certificate this run did not issue): the connection must be refused, not
downgraded.
"""

from __future__ import annotations

import os

import psycopg
import pytest

from deploy.config import configure_transport
from tests.security.conftest import skip_or_fail_without_postgres
from wire.tls import generate

_DATABASE_URL = os.environ.get("DATABASE_URL")


@pytest.fixture()
def plaintext_store():
    if not _DATABASE_URL:
        skip_or_fail_without_postgres("DATABASE_URL not set; store TLS test skipped")
    try:
        # Setup is valid: the store accepts this client outside the TLS profile.
        psycopg.connect(_DATABASE_URL).close()
    except psycopg.OperationalError as exc:
        skip_or_fail_without_postgres(f"cannot reach Postgres: {exc}")
    return _DATABASE_URL


def test_tls_profile_refuses_a_store_without_verified_tls(
    plaintext_store, monkeypatch, tmp_path
):
    generate(tmp_path)
    monkeypatch.setenv("TLS_ENABLED", "true")
    monkeypatch.setenv("TLS_CERT_DIR", str(tmp_path))
    for name in ("SSL_CERT_FILE", "PGSSLMODE", "PGSSLROOTCERT"):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)
    configure_transport()

    with pytest.raises(psycopg.OperationalError) as refused:
        psycopg.connect(plaintext_store).close()
    # Refused for TLS, not for an unrelated reason such as a wrong password.
    message = str(refused.value)
    assert "SSL" in message or "certificate" in message, message
