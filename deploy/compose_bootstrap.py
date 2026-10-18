"""Path B one-shot bootstrap step: the Compose ``bootstrap`` service (P4-3).

Runs after every long-running service reports healthy
(``depends_on: condition: service_healthy`` in ``docker-compose.yml``).
Performs the same sequence ``deploy/run_local.py`` performs for Path A --
PKI generation, authority registration, and the hard boot precondition that
the audit chain verifies -- but against service hostnames on the Compose
bridge network instead of localhost ports.

Environment:
    DATABASE_URL, AUDIT_SERVICE_URL, AUTHORITY_MED_URL, AUTHORITY_NET_URL,
    FACILITY_A_URL, FACILITY_B_URL, CUSTODIAN_URL: set by
    ``docker-compose.yml``.
    SEED_DATA: ``false`` skips seeding the synthetic dataset (default on).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx
import psycopg
from psycopg.types.json import Jsonb

from deploy import bootstrap
from deploy.config import configure_transport
from deploy.run_scenario import ScenarioEndpoints

FEDERATION_CONFIG_PATH = Path("/pki/federation.json")
FEDERATION_PKI_PATH = Path("/pki/federation-pki.json")
SERVICES_DIR = Path("/pki/services")


def main() -> int:
    """Run bootstrap steps 1-3 and 7 against the Compose network, then exit."""
    configure_transport()
    database_url = os.environ["DATABASE_URL"]
    audit_url = os.environ["AUDIT_SERVICE_URL"]
    custodian_url = os.environ["CUSTODIAN_URL"]

    authority_urls = {
        "authority-med": os.environ["AUTHORITY_MED_URL"],
        "authority-net": os.environ["AUTHORITY_NET_URL"],
    }

    facility_urls = {
        "facility-a": os.environ["FACILITY_A_URL"],
        "facility-b": os.environ["FACILITY_B_URL"],
    }

    try:
        print("[1/7] applying database migrations...")
        applied = bootstrap.run_migrations(database_url)
        print(f"      applied: {applied or 'nothing to apply'}")
        urls = {
            **authority_urls,
            **facility_urls,
            "audit": audit_url,
            "custodian": custodian_url,
        }
        instances = service_instances(urls)
        with psycopg.connect(database_url) as conn:
            completed = conn.execute(
                "SELECT instances, seeded FROM deployment_bootstrap WHERE singleton"
            ).fetchone()
            populated = conn.execute("SELECT count(*) FROM facilities").fetchone()[0]
        if completed:
            if completed != (instances, bootstrap.seed_enabled()):
                raise bootstrap.BootstrapError(
                    "services restarted or seed mode changed; recreate the entire demo "
                    "with docker compose down, then up --build"
                )
            bootstrap.check_audit_chain(audit_url)
            print(
                "federation already bootstrapped; instances and audit chain verified."
            )
            return 0
        if populated:
            raise bootstrap.BootstrapError(
                "previous bootstrap incomplete; recreate the entire demo with "
                "docker compose down, then up --build"
            )

        print("[2/7] loading the federation PKI the pki job generated...")
        # Generated before the facilities started, which loaded its trust
        # anchors at startup (review F1); see deploy/compose_pki.py.
        root, pki = bootstrap.load_federation_pki(FEDERATION_PKI_PATH)
        # Every call below is signed as bootstrap (ADR-0066).
        client = bootstrap.bootstrap_client(
            bootstrap.load_service_identity_dir(SERVICES_DIR, "bootstrap"),
            authorities=authority_urls,
            facilities=facility_urls,
            audit=audit_url,
            custodian=custodian_url,
        )

        print("[3/7] waiting for authority services and registering them...")
        authority_certificates: dict[str, str] = {}

        for authority_id, base_url in authority_urls.items():
            bootstrap.wait_for_health(base_url)
            authority_certificates[authority_id] = bootstrap.register_authority(
                base_url,
                root,
                authority_id,
                client=client,
            )

        print("[4/7] waiting for the audit service...")
        bootstrap.wait_for_health(audit_url)

        print("[5/7] waiting for facility nodes...")
        for base_url in facility_urls.values():
            bootstrap.wait_for_health(base_url)

        print("[6/7] registering federation members and seeding synthetic data...")
        bootstrap.populate_registry(database_url, pki, authority_urls, facility_urls)
        config = bootstrap.write_federation_config(
            FEDERATION_CONFIG_PATH,
            pki,
            authority_certificates,
            authority_urls,
            audit_url,
        )
        print(f"      federation config written to {FEDERATION_CONFIG_PATH}")
        if bootstrap.seed_enabled():
            endpoints = ScenarioEndpoints(
                authority_med=authority_urls["authority-med"],
                authority_net=authority_urls["authority-net"],
                audit=audit_url,
                facility_a=facility_urls["facility-a"],
                facility_b=facility_urls["facility-b"],
                custodian=custodian_url,
            )
            summary = bootstrap.seed_federation(
                endpoints, config, custodian_url, client=client
            )
            print(f"      {summary}")
        else:
            print("      SEED_DATA=false -- seeding skipped")

        print("[7/7] verifying the audit chain from genesis...")
        head_seq = bootstrap.check_audit_chain(audit_url)
        if service_instances(urls) != instances:
            raise bootstrap.BootstrapError("a service restarted during bootstrap")
        with psycopg.connect(database_url) as conn:
            conn.execute(
                "INSERT INTO deployment_bootstrap (instances, seeded) VALUES (%s, %s)",
                (Jsonb(instances), bootstrap.seed_enabled()),
            )
        print(f"      chain verified, head seq={head_seq}")
        print("\nfederation is up.")

    except Exception as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 1

    return 0


def service_instances(urls: dict[str, str]) -> dict[str, str]:
    """Read live process IDs so stale in-memory keys cannot pass a retry."""
    with httpx.Client(timeout=10.0) as client:
        instances = {}
        for name, url in urls.items():
            response = client.get(f"{url}/deployment/instance")
            response.raise_for_status()
            instances[name] = response.json()["instance_id"]
        return instances


if __name__ == "__main__":
    sys.exit(main())
