"""Path B one-shot bootstrap step: the Compose ``bootstrap`` service (P4-3).

Runs after every long-running service reports healthy
(``depends_on: condition: service_healthy`` in ``docker-compose.yml``).
Performs the same sequence ``deploy/run_local.py`` performs for Path A --
PKI generation, authority registration, and the hard boot precondition that
the audit chain verifies -- but against service hostnames on the Compose
bridge network instead of localhost ports.

Environment:
    DATABASE_URL, AUDIT_SERVICE_URL, AUTHORITY_MED_URL, AUTHORITY_NET_URL,
    FACILITY_A_URL, FACILITY_B_URL: set by ``docker-compose.yml``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from deploy import bootstrap

FEDERATION_CONFIG_PATH = Path("/pki/federation.json")


def main() -> int:
    """Run bootstrap steps 1-3 and 7 against the Compose network, then exit."""
    database_url = os.environ["DATABASE_URL"]
    audit_url = os.environ["AUDIT_SERVICE_URL"]
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

        print("[2/7] generating federation PKI (root anchor + facility CAs)...")
        root, pki = bootstrap.generate_federation_pki(list(facility_urls))

        print("[3/7] waiting for authority services and registering them...")
        authority_certificates: dict[str, str] = {}
        for authority_id, base_url in authority_urls.items():
            bootstrap.wait_for_health(base_url)
            authority_certificates[authority_id] = bootstrap.register_authority(
                base_url, root, authority_id
            )

        print("[4/7] waiting for the audit service...")
        bootstrap.wait_for_health(audit_url)

        print("[5/7] waiting for facility nodes...")
        for base_url in facility_urls.values():
            bootstrap.wait_for_health(base_url)

        print(
            "[6/7] seeding synthetic data -- left to the demo driver (P4-5); "
            "skipped here."
        )

        print("[7/7] verifying the audit chain from genesis...")
        head_seq = bootstrap.check_audit_chain(audit_url)
        print(f"      chain verified, head seq={head_seq}")

        bootstrap.write_federation_config(
            FEDERATION_CONFIG_PATH,
            pki,
            authority_certificates,
            authority_urls,
            audit_url,
        )
        print(f"federation config written to {FEDERATION_CONFIG_PATH}")
        print("\nfederation is up.")
    except bootstrap.BootstrapError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
