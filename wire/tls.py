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

# Bounded lifetime -- ARCHITECTURE.md §8 "nothing issues forever"; long enough
# to outlive a demo/capture run, short enough that a stray cert is not durable.
_TLS_VALID_DAYS = 90


def generate(output_dir: Path) -> None:
    """Create one self-signed local certificate per federation service."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for service in SERVICES:
        priv, _pub = generate_ec_keypair()
        cert = build_self_signed_tls_cert(
            signing_key=priv,
            common_name=service,
            dns_names=(service, "localhost"),
            ip_addresses=("127.0.0.1",),
            valid_days=_TLS_VALID_DAYS,
        )
        (output_dir / f"{service}.key").write_bytes(private_key_to_pem(priv))
        (output_dir / f"{service}.crt").write_bytes(certificate_to_pem(cert))

    print(f"TLS certificates written to {output_dir}")


if __name__ == "__main__":
    generate(Path("wire/certs"))
