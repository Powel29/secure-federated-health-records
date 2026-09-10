"""Command-line entrypoint for the Federated Break-Glass EHR demo (P4-5).

Usage:
    python -m demo.run_demo [options]
    python -m demo [options]
"""

from __future__ import annotations

import sys

from demo.driver import main

if __name__ == "__main__":
    sys.exit(main())
