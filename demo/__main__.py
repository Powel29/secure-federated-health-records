"""Direct module execution entrypoint for demo package (`python -m demo`)."""

from __future__ import annotations

import sys

from demo.driver import main

if __name__ == "__main__":
    sys.exit(main())
