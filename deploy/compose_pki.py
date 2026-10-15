"""Path B one-shot job: generate the federation PKI before the facilities start.

Facilities load the break-glass trust anchors (federation root and the
cross-certified facility CAs) at startup and never accept them from a request
(review F1), so the PKI has to exist before they start. Compose runs this
before every facility; ``deploy.compose_bootstrap`` later loads the same PKI
to register the authorities and seed clinicians.

Writes, under the git-ignored ``/pki`` mount (``deploy/pki/``):
    federation-pki.json: root and facility CA private keys plus certificates,
        read only by the bootstrap job.
    trust/: the certificates alone, the only directory facilities mount.
    services/<service_id>/: each service's request-signing key and root
        certificate (ADR-0066); each container mounts only its own.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from deploy import bootstrap

PKI_DIR = Path("/pki")
FACILITY_IDS = ["facility-a", "facility-b"]
# The unprivileged user every service container runs as (deploy/Dockerfile).
SERVICE_USER = "app"


def hand_to_service_user(directory: Path) -> None:
    """Give the service identity files to the containers' ``app`` user.

    This job runs as root and writes each key owner-only (0600); a service
    container runs as ``app`` and must read its own key. Ownership changes,
    the mode does not, and each container mounts only its own directory.
    """
    try:
        import pwd
    except ImportError:  # not in a container (Windows host): nothing to do
        return
    try:
        user = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        return
    for path in [directory, *directory.rglob("*")]:
        os.chown(path, user.pw_uid, user.pw_gid)


def main() -> int:
    """Generate a fresh federation PKI (ADR-0039) and write it out."""
    root, pki = bootstrap.generate_federation_pki(FACILITY_IDS)
    bootstrap.save_federation_pki(PKI_DIR / "federation-pki.json", root, pki)
    bootstrap.write_trust_bundle(PKI_DIR / "trust", pki)
    bootstrap.write_service_identities(
        PKI_DIR / "services", bootstrap.issue_service_identities(root)
    )
    hand_to_service_user(PKI_DIR / "services")
    print(f"federation PKI written to {PKI_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
