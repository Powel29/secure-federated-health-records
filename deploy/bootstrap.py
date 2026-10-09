"""Deployment bootstrap sequence (P4-3, ARCHITECTURE.md §7).

Implements the parts of the seven-step bootstrap sequence that are not
"start a process": generating the federation's PKI, registering each
attribute authority's certificate with the root anchor, and the hard boot
precondition that the audit chain verifies before anything is allowed to
proceed. Starting the five service processes themselves is each deployment
path's own job -- ``deploy/run_local.py`` for Path A (local subprocesses),
``docker-compose.yml`` + ``deploy/compose_bootstrap.py`` for Path B (as the
one-shot ``bootstrap`` Compose service, gated on every other service's
``depends_on: condition: service_healthy``).

Steps below are numbered to match ARCHITECTURE.md §7 exactly:
    1. :func:`generate_federation_pki` -- root anchor + facility CA certs.
    2. Cross-certification is implicit: every facility CA is signed by the
       same root (ADR-0024), so nothing further is needed here.
    3. :func:`register_authority`, once per authority -- fetch its public
       key, have the root sign a certificate for it, hand the certificate
       back.
    4/5. Starting the audit service and the facility nodes is each caller's
       job, not this module's.
    6. :func:`populate_registry` + :func:`seed_federation` -- record the
       authorities, facility nodes and synthetic patients' identifiers in
       the store,
       then ingest the synthetic dataset (P4-5)
       and deposit its key material with the custodian (ADR-0043). Seeding
       is skipped when ``SEED_DATA=false`` (e.g. to run ``python -m
       demo.driver``, which seeds the same dataset itself).
    7. :func:`wait_for_health` + :func:`check_audit_chain` -- the hard boot
       precondition.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import httpx
import psycopg
from contracts import Facility
from contracts.enums import FacilityStatus
from crypto_core import (
    certificate_from_pem,
    certificate_to_pem,
    generate_ec_keypair,
    private_key_to_pem,
    public_key_from_pem,
    public_key_to_pem,
)
from identity.certificates import (
    issue_authority_certificate,
    issue_facility_ca_certificate,
)
from identity.root_anchor import RootAnchor, generate_root_anchor
from psycopg.conninfo import conninfo_to_dict
from storage.migrate import apply_migrations, reset_schema
from storage.repositories import insert_authority, insert_facility, insert_patient

from demo.seed_data import create_synthetic_dataset, seed_synthetic_data
from deploy.run_scenario import ScenarioEndpoints
from deploy.seed_portal import deposit_custodian


class BootstrapError(RuntimeError):
    """The bootstrap sequence could not complete -- fail closed, start nothing."""


def _http_verify() -> bool:
    """Return whether HTTPS certificate verification is enabled."""
    return os.environ.get("TLS_VERIFY", "true").lower() not in {"0", "false", "no"}


@dataclass(frozen=True)
class FacilityPKI:
    """One facility's CA keypair and root-issued certificate, serialized."""

    facility_id: str
    ca_private_key_pem: str
    ca_certificate_pem: str


@dataclass(frozen=True)
class FederationPKI:
    """The federation's root certificate plus every facility's CA material."""

    root_certificate_pem: str
    facilities: dict[str, FacilityPKI]


def seed_enabled() -> bool:
    """Whether bootstrap step 6 seeds the synthetic dataset (``SEED_DATA``)."""
    return os.environ.get("SEED_DATA", "true").lower() not in {"0", "false", "no"}


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _require_local_database(database_url: str) -> None:
    """Refuse a destructive reset unless the DSN can only reach this machine."""
    params = conninfo_to_dict(database_url)
    targets = [
        params.get("host") or os.environ.get("PGHOST", ""),
        params.get("hostaddr") or os.environ.get("PGHOSTADDR", ""),
    ]
    for target in targets:
        for host in filter(None, target.split(",")):
            # A leading "/" is a Unix-socket directory, which is local.
            if host not in _LOCAL_HOSTS and not host.startswith("/"):
                raise BootstrapError(
                    f"refusing to drop the schema on non-local host {host!r}"
                )


def run_migrations(database_url: str, *, reset: bool = False) -> list[str]:
    """Apply the shared store's schema migrations (ARCHITECTURE.md §7, P0-8).

    Args:
        database_url: DSN for the shared Postgres store.
        reset: Drop the ``public`` schema first -- a fresh federation's new
            audit key cannot verify a previous run's chain (ADR-0039).
            Refused unless every target host is loopback or a local socket.

    Returns:
        The migration filenames that were newly applied (empty if the
        schema was already up to date).

    Raises:
        BootstrapError: ``reset`` was requested against a non-local host.
    """
    if reset:
        _require_local_database(database_url)
    conn = psycopg.connect(database_url)
    try:
        if reset:
            reset_schema(conn)
        applied = apply_migrations(conn)
        conn.commit()
    finally:
        conn.close()
    return applied


def generate_federation_pki(
    facility_ids: list[str],
) -> tuple[RootAnchor, FederationPKI]:
    """Bootstrap steps 1-2: root anchor + cross-certified facility CAs.

    Every facility CA is signed by the same root (ADR-0019/ADR-0024), which
    is what makes cross-certification a consequence of this single step
    rather than a separate one.

    Args:
        facility_ids: The facilities to issue CA certificates for.

    Returns:
        The live :class:`RootAnchor` (needed next, to sign authority
        certificates) and the serializable :class:`FederationPKI` written to
        disk for later consumers -- a seed/demo script, not this task's to
        build.
    """
    root = generate_root_anchor()
    facilities: dict[str, FacilityPKI] = {}
    for facility_id in facility_ids:
        ca_private_key, ca_public_key = generate_ec_keypair()
        ca_certificate = issue_facility_ca_certificate(root, facility_id, ca_public_key)
        facilities[facility_id] = FacilityPKI(
            facility_id=facility_id,
            ca_private_key_pem=private_key_to_pem(ca_private_key).decode("ascii"),
            ca_certificate_pem=certificate_to_pem(ca_certificate).decode("ascii"),
        )
    pki = FederationPKI(
        root_certificate_pem=certificate_to_pem(root.certificate).decode("ascii"),
        facilities=facilities,
    )
    return root, pki


def wait_for_health(
    base_url: str, *, timeout: float = 30.0, interval: float = 0.5
) -> None:
    """Poll ``GET {base_url}/health`` until it succeeds or ``timeout`` elapses.

    Args:
        base_url: The service's base URL, e.g. ``"http://127.0.0.1:8010"``.
        timeout: Total seconds to keep polling before giving up.
        interval: Seconds to wait between attempts.

    Raises:
        BootstrapError: The service never reported healthy in time.
    """
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(
                f"{base_url}/health", timeout=interval, verify=_http_verify()
            )
            if resp.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_exc = exc
        time.sleep(interval)
    raise BootstrapError(
        f"{base_url} did not become healthy within {timeout}s: {last_exc}"
    )


def register_authority(
    base_url: str, root: RootAnchor, authority_id: str, *, timeout: float = 10.0
) -> str:
    """Bootstrap step 3: fetch an authority's public key, sign it, register it back.

    Args:
        base_url: The authority service's base URL.
        root: The federation's root anchor.
        authority_id: The authority's identifier (must match how the
            service itself was started, e.g. ``"authority-med"``).
        timeout: Per-request HTTP timeout in seconds.

    Returns:
        The authority's certificate PEM -- already handed back to the
        service via ``PUT /certificate``, so ``GET /certificate`` now
        returns it too.
    """
    resp = httpx.get(f"{base_url}/public-key", timeout=timeout, verify=_http_verify())
    resp.raise_for_status()
    public_key = public_key_from_pem(resp.json()["public_key_pem"].encode("ascii"))

    certificate = issue_authority_certificate(root, authority_id, public_key)
    certificate_pem = certificate_to_pem(certificate).decode("ascii")

    resp = httpx.put(
        f"{base_url}/certificate",
        json={"certificate_pem": certificate_pem},
        timeout=timeout,
        verify=_http_verify(),
    )
    resp.raise_for_status()
    return certificate_pem


def populate_registry(
    database_url: str,
    pki: FederationPKI,
    authority_endpoints: dict[str, str],
    facility_endpoints: dict[str, str],
) -> None:
    """Bootstrap step 6a: record the authorities, facilities and patient ids.

    Records reference ``facilities`` and ``patients`` (and patients reference
    ``authorities``) by foreign key, so ingest fails until this runs. Each
    authority row carries the service's own public key, each facility row
    its root-issued CA key; patient rows carry only identifier + home
    authority (no PHI), for the synthetic dataset's patients -- the ones
    every seed path and scenario ingests records for.

    Args:
        database_url: DSN for the shared Postgres store.
        pki: The federation PKI from :func:`generate_federation_pki`.
        authority_endpoints: ``authority_id -> base_url``.
        facility_endpoints: ``facility_id -> base_url``.
    """
    with psycopg.connect(database_url) as conn:
        for authority_id, base_url in authority_endpoints.items():
            resp = httpx.get(
                f"{base_url}/public-key", timeout=10.0, verify=_http_verify()
            )
            resp.raise_for_status()
            insert_authority(
                conn,
                authority_id,
                authority_id.replace("-", " ").title(),
                resp.json()["public_key_pem"].encode("ascii"),
            )
        for facility_id, endpoint in facility_endpoints.items():
            ca_certificate = certificate_from_pem(
                pki.facilities[facility_id].ca_certificate_pem.encode("ascii")
            )
            insert_facility(
                conn,
                Facility(
                    facility_id=facility_id,
                    display_name=facility_id.replace("-", " ").title(),
                    endpoint=endpoint,
                    public_key=public_key_to_pem(ca_certificate.public_key()),
                    status=FacilityStatus.ACTIVE,
                ),
            )
        for patient in create_synthetic_dataset().patients:
            insert_patient(conn, patient.patient_id, patient.owner_authority)


def seed_federation(
    endpoints: ScenarioEndpoints, config: dict[str, Any], custodian_url: str
) -> str:
    """Bootstrap step 6b: ingest the synthetic dataset and fill the custodian.

    ``seed_synthetic_data`` writes the patient rows itself, so
    ``DATABASE_URL`` must be set in the environment.

    Args:
        endpoints: The five federation services' base URLs.
        config: The payload from :func:`write_federation_config`.
        custodian_url: The key custodian's base URL.

    Returns:
        A one-line summary for the bootstrap log.
    """
    seed = seed_synthetic_data(endpoints, config)
    counts = deposit_custodian(custodian_url, seed)
    return (
        f"{len(seed['records'])} records ingested; custodian holds "
        f"{counts['subjects']} subjects and {counts['shares']} clinician shares"
    )


def check_audit_chain(base_url: str, *, timeout: float = 10.0) -> int:
    """Bootstrap step 7: the hard boot precondition.

    ARCHITECTURE.md §7: "if chain verification fails at boot, nothing else
    starts."

    Args:
        base_url: The audit service's base URL.
        timeout: HTTP request timeout in seconds.

    Returns:
        The verified chain head's ``seq``.

    Raises:
        BootstrapError: The service could not be reached, the chain is
            empty, or verification failed.
    """
    try:
        resp = httpx.get(
            f"{base_url}/chain/verify", timeout=timeout, verify=_http_verify()
        )
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise BootstrapError(f"cannot verify audit chain at {base_url}: {exc}") from exc
    body = resp.json()
    if not body["verified"]:
        raise BootstrapError(
            f"audit chain at {base_url} failed verification; refusing to continue"
        )
    return body["head_seq"]


def write_federation_config(
    path: Path,
    pki: FederationPKI,
    authority_certificates: dict[str, str],
    authority_endpoints: dict[str, str],
    audit_endpoint: str,
) -> dict[str, Any]:
    """Persist the federation's public trust material for later consumers.

    Written under ``deploy/pki/`` (or a mounted equivalent), which is
    ``.gitignore``d in its entirety (WORKFLOW.md §4). This file carries each
    facility's CA *private* key too -- needed downstream to issue clinician
    certificates -- which is exactly why the whole file must never be
    committed.

    Args:
        path: Destination file path; parent directories are created.
        pki: The federation PKI from :func:`generate_federation_pki`.
        authority_certificates: ``authority_id -> certificate_pem`` from
            :func:`register_authority`.
        authority_endpoints: ``authority_id -> base_url``.
        audit_endpoint: The audit service's base URL.

    Returns:
        The payload written (the ``config`` :func:`seed_federation` takes).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "root_certificate_pem": pki.root_certificate_pem,
        "facilities": {
            facility_id: asdict(facility)
            for facility_id, facility in pki.facilities.items()
        },
        "authorities": {
            authority_id: {
                "certificate_pem": authority_certificates[authority_id],
                "endpoint": authority_endpoints[authority_id],
            }
            for authority_id in authority_certificates
        },
        "audit": {"endpoint": audit_endpoint},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
