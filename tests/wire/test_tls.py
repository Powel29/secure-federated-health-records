"""Tests for the P4-6 TLS cert generation (wire/tls.py).

Verifies the capture-harness certs are well-formed, carry the right SANs, are
bounded in time, and -- the point of the fix -- that generation goes through
``crypto_core`` with no direct hazmat import in ``wire``.
"""

from __future__ import annotations

import datetime

from crypto_core import certificate_from_pem
from cryptography import x509

import wire.tls as tls_mod
from wire.tls import SERVICES, generate


def test_generate_writes_a_cert_and_key_per_service(tmp_path):
    generate(tmp_path)
    for service in SERVICES:
        assert (tmp_path / f"{service}.crt").exists()
        assert (tmp_path / f"{service}.key").exists()


def test_cert_has_expected_sans_and_cn(tmp_path):
    generate(tmp_path)
    cert = certificate_from_pem((tmp_path / "facility-a.crt").read_bytes())

    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    assert cn == "facility-a"

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = set(san.get_values_for_type(x509.DNSName))
    ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    assert {"facility-a", "localhost"} <= dns
    assert "127.0.0.1" in ips


def test_cert_validity_is_bounded_not_forever(tmp_path):
    """ARCHITECTURE.md §8: nothing issues forever -- not even a capture cert."""
    generate(tmp_path)
    cert = certificate_from_pem((tmp_path / "audit.crt").read_bytes())
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert lifetime <= datetime.timedelta(days=366)


def test_wire_tls_imports_no_hazmat():
    """The whole reason for the fix: wire/ must not import cryptography directly.

    Scans the actual import statements (not docstring prose), matching the
    CONVENTIONS.md §2 rule 1 guard: all primitives go through ``crypto_core``.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(tls_mod))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    assert not any(name.startswith("cryptography") for name in imported), imported
