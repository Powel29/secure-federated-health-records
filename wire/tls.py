"""Generate local-only TLS certificates for the P4-6 traffic-capture harness.

TLS here exists only so the capture harness can record an *encrypted* wire in
the ``capture-tls`` profile and prove no plaintext leaks even without TLS
termination in front. These are throwaway, localhost-only server certs.

All certificate/key primitives go through ``crypto_core`` (CONVENTIONS.md §2
rule 1) -- this module holds no ``cryptography.hazmat`` imports of its own.
"""

from __future__ import annotations

from pathlib import Path

from crypto_core import (
    build_self_signed_tls_cert,
    certificate_to_pem,
    generate_ec_keypair,
    private_key_to_pem,
)

SERVICES = {
    "authority-med": 8010,
    "authority-net": 8011,
    "audit": 8020,
    "facility-a": 8001,
    "facility-b": 8002,
    "custodian": 8030,  # Key Custodian (ADR-0043); same TLS profile as the rest
}

# The federation's Postgres (Compose service name ``store``). It is not an HTTP
# service, so it is not in SERVICES (whose ports the capture and checks treat
# as service ports); its certificate is trusted only by database clients,
# through its own file rather than the HTTP bundle (ADR-0071).
STORE = "store"
STORE_ROOT_CERT = "store.crt"

# Bounded lifetime -- ARCHITECTURE.md §8 "nothing issues forever"; long enough
# to outlive a demo/capture run, short enough that a stray cert is not durable.
_TLS_VALID_DAYS = 90


def generate(output_dir: Path) -> None:
    """Create one self-signed local certificate per federation service.

    Each service's key and certificate go in ``<output_dir>/<service>/`` and
    the shared client trust bundle in ``<output_dir>/trust/``, so a container
    can mount only its own key plus the bundle (ADR-0047). The store's
    certificate is written the same way and trusted separately, as
    ``trust/store.crt`` (ADR-0071).
    """
    certificates = [_write_server_cert(output_dir, service) for service in SERVICES]
    store_cert = _write_server_cert(output_dir, STORE)

    # Trust the exact demo servers instead of disabling certificate verification.
    trust_dir = output_dir / "trust"
    trust_dir.mkdir(parents=True, exist_ok=True)
    (trust_dir / "ca-bundle.crt").write_bytes(b"".join(certificates))
    (trust_dir / STORE_ROOT_CERT).write_bytes(store_cert)

    print(f"TLS certificates written to {output_dir}")


def _write_server_cert(output_dir: Path, name: str) -> bytes:
    """Write ``<name>/<name>.{key,crt}`` and return the certificate PEM."""
    priv, _pub = generate_ec_keypair()
    cert = build_self_signed_tls_cert(
        signing_key=priv,
        common_name=name,
        dns_names=(name, "localhost"),
        ip_addresses=("127.0.0.1",),
        valid_days=_TLS_VALID_DAYS,
    )
    service_dir = output_dir / name
    service_dir.mkdir(parents=True, exist_ok=True)
    (service_dir / f"{name}.key").write_bytes(private_key_to_pem(priv))
    cert_pem = certificate_to_pem(cert)
    (service_dir / f"{name}.crt").write_bytes(cert_pem)
    return cert_pem


if __name__ == "__main__":
    generate(Path("wire/certs"))
