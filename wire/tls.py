"""Generate local-only TLS certificates for the P4-6 traffic-capture harness."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


SERVICES = {
    "authority-med": 8010,
    "authority-net": 8011,
    "audit": 8020,
    "facility-a": 8001,
    "facility-b": 8002,
}


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def generate(output_dir: Path) -> None:
    """Create one self-signed local certificate per federation service."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for service, port in SERVICES.items():
        key = ec.generate_private_key(ec.SECP256R1())

        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, service)]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(__import__("datetime").datetime.now(
                __import__("datetime").timezone.utc
            ))
            .not_valid_after(
                __import__("datetime").datetime.now(
                    __import__("datetime").timezone.utc
                ).replace(year=2036)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName(service),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        _write_key(output_dir / f"{service}.key", key)
        _write_cert(output_dir / f"{service}.crt", cert)

    print(f"TLS certificates written to {output_dir}")


if __name__ == "__main__":
    generate(Path("wire/certs"))
