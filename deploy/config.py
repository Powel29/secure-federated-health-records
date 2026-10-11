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


_TRUE = {"1", "true", "yes"}
_FALSE = {"0", "false", "no"}


def env_flag(name: str, default: bool = False) -> bool:
    """Read a yes/no environment variable; one parser for every deploy flag.

    Unset or empty gives ``default``; ``1/true/yes`` and ``0/false/no`` are
    the only other accepted values (review N14).

    Raises:
        ValueError: The variable holds anything else.
    """
    value = os.environ.get(name, "").strip().lower()
    if not value:
        return default
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name}={value!r} is not one of {sorted(_TRUE | _FALSE)}")


def tls_enabled() -> bool:
    """Whether the local TLS profile is selected."""
    return env_flag("TLS_ENABLED")


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
