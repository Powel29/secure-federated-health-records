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
"""

from __future__ import annotations

import sys
from pathlib import Path

from deploy import bootstrap

PKI_DIR = Path("/pki")
FACILITY_IDS = ["facility-a", "facility-b"]


def main() -> int:
    """Generate a fresh federation PKI (ADR-0039) and write it out."""
    root, pki = bootstrap.generate_federation_pki(FACILITY_IDS)
    bootstrap.save_federation_pki(PKI_DIR / "federation-pki.json", root, pki)
    bootstrap.write_trust_bundle(PKI_DIR / "trust", pki)
    print(f"federation PKI written to {PKI_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
