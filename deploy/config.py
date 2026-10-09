"""Transport configuration shared by local and Compose entrypoints."""

from __future__ import annotations

import os
from pathlib import Path

_URL_VARIABLES = (
    "AUDIT_SERVICE_URL",
    "AUTHORITY_MED_URL",
    "AUTHORITY_NET_URL",
    "FACILITY_A_URL",
    "FACILITY_B_URL",
    "CUSTODIAN_URL",
    "AUTHORITY_URLS",
    "FACILITY_URLS",
)


def tls_enabled() -> bool:
    """Whether the local TLS profile is selected."""
    return os.environ.get("TLS_ENABLED", "").lower() in {"1", "true", "yes"}


def configure_transport(service_name: str | None = None) -> None:
    """Select HTTPS endpoints and trust the generated local certificate bundle."""
    if not tls_enabled():
        return
    cert_dir = Path(os.environ.get("TLS_CERT_DIR", "wire/certs")).resolve()
    bundle = Path(
        os.environ.get("SSL_CERT_FILE", str(cert_dir / "trust" / "ca-bundle.crt"))
    )
    if not bundle.is_file():
        raise RuntimeError("TLS trust bundle missing; run python -m wire.tls first")
    os.environ["SSL_CERT_FILE"] = str(bundle)
    for name in _URL_VARIABLES:
        if name in os.environ:
            os.environ[name] = os.environ[name].replace("http://", "https://")
    if service_name:
        os.environ.setdefault(
            "SSL_CERTFILE", str(cert_dir / service_name / f"{service_name}.crt")
        )
        os.environ.setdefault(
            "SSL_KEYFILE", str(cert_dir / service_name / f"{service_name}.key")
        )
