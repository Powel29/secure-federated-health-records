"""Apply the store's migrations under the deployment's transport profile.

``python -m storage.migrate`` with the TLS profile's Postgres settings
applied first (ADR-0071), so the Compose ``migrate`` job reaches a TLS-only
store the same way every service does.
"""

from __future__ import annotations

import sys

from storage.migrate import main as migrate

from deploy.config import configure_transport


def main() -> int:
    configure_transport()
    return migrate()


if __name__ == "__main__":
    sys.exit(main())
