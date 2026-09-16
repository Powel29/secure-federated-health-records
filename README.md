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

Verify (same scope as CI):

```bash
pytest; ruff check src/ tests/; black --check src/ tests/
```

The `storage` tests need PostgreSQL (see below) and **skip cleanly without it**,
so a clone without a database still runs green. The Django portals have their own
test suite — see [portal/README.md](portal/README.md).

## Database (PostgreSQL)

The shared store (C4) is PostgreSQL (`ADR-0014`/`ADR-0020`). Bring up a throwaway
instance with Docker, then apply the schema:

```bash
docker run -d --name p08pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr_test -p 55432:5432 postgres:16-alpine
```

```bash
DATABASE_URL="postgresql://postgres@localhost:55432/ehr_test" python -m storage.migrate
```

With `DATABASE_URL` set, the storage tests run the real read/write round-trips:

```bash
DATABASE_URL="postgresql://postgres@localhost:55432/ehr_test" pytest tests/storage/
```

(PowerShell: prefix with `$env:DATABASE_URL="…";` instead of the inline form.)

## Running the federation

Two ways to bring up all six processes (shared store, two facilities, two
attribute authorities, the audit service) with the bootstrap sequence
ARCHITECTURE.md §7 describes — a local supervisor script (no Docker) and
Docker Compose. See [deploy/README.md](deploy/README.md).

## Web portals

Three role-based Django portals (patient / clinician / admin-audit) plus
self-service registration live in [`portal/`](portal/). They identify users and
show data; they never decide access or decrypt (`ADR-0014`/`ADR-0021`); anything
that needs a key goes to the Key Custodian service (`ADR-0043`). One command
brings up the federation, the custodian, the seeded dataset and the portals:

```bash
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/mydb python -m deploy.run_portal_demo
```

Logins, the examiner walk-through and the multi-process variant are in
[portal/README.md](portal/README.md).

## External tools

`pip` cannot install these. Both are needed for the traffic-analysis module
(C17, the required course module — see `PROJECT.md` §4A):

- **Wireshark / tshark**, on `PATH`. `pyshark` is only a wrapper around the
  `tshark` binary; `import pyshark` succeeding does not mean capture works.
  Check with `tshark --version`.
- **Docker Desktop**, for the Compose deployment path (`ARCHITECTURE.md` §7) and
  for the local PostgreSQL used by the storage tests and the portals (above).
  The local multi-process path itself works without it.

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
