# Secure Federated Health Records

Federated Break-Glass EHR with a Unified Key-Lifecycle State Machine.
Information Security lab project (ICT 3121).

Start with [CLAUDE.md](CLAUDE.md), which routes to the four project documents:
[PROJECT.md](PROJECT.md) (scope), [ARCHITECTURE.md](ARCHITECTURE.md) (design),
[CONVENTIONS.md](CONVENTIONS.md) (code rules), [WORKFLOW.md](WORKFLOW.md)
(who does what, when).

---

## Setup

Requires **Python 3.11 or newer**. Check with `python --version` before starting.

```bash
python -m venv .venv
```

Activate it — Windows PowerShell:

```bash
.venv\Scripts\Activate.ps1
```

macOS / Linux:

```bash
source .venv/bin/activate
```

Then install. Use the dev file; it pulls in `requirements.txt` and installs the
project itself in editable mode:

```bash
pip install -r requirements-dev.txt
```

Verify:

```bash
pytest && ruff check . && black --check .
```

An empty test suite passing is the expected result until Phase 1 lands.

## External tools

`pip` cannot install these. Both are needed for the traffic-analysis module
(C17, the required course module — see `PROJECT.md` §4A):

- **Wireshark / tshark**, on `PATH`. `pyshark` is only a wrapper around the
  `tshark` binary; `import pyshark` succeeding does not mean capture works.
  Check with `tshark --version`.
- **Docker Desktop**, for the Compose deployment path (`ARCHITECTURE.md` §7).
  The local five-process path works without it.

## Imports

`src/` is a src-layout package root, so modules are imported by their bare
names — the `src.` prefix is not part of the import path:

```python
from contracts import Record        # correct
from src.contracts import Record    # wrong, will not resolve
```

This works because `requirements-dev.txt` installs the project with `-e .`.
`pytest` additionally sets `pythonpath = ["src"]` so the suite runs from a clean
clone even before an install.

## Layout

Directory structure and what each module owns:
[ARCHITECTURE.md §6](ARCHITECTURE.md). One owner per `src/` module — do not edit
another member's directory ([CONVENTIONS.md §3](CONVENTIONS.md)).

## Before your first commit

Read [CONVENTIONS.md](CONVENTIONS.md) — especially §2, the seven crypto rules,
which are correctness requirements rather than preferences. Never commit key
material, including test keys; `.gitignore` covers the usual extensions, but it
is a safety net, not a substitute for checking `git status`.
