# Secure Federated Health Records

Federated Break-Glass EHR with a Unified Key-Lifecycle State Machine.
Information Security lab project (ICT 3121).

Start with [CLAUDE.md](CLAUDE.md), which routes to the four project documents:
[PROJECT.md](PROJECT.md) (scope), [ARCHITECTURE.md](ARCHITECTURE.md) (design),
[CONVENTIONS.md](CONVENTIONS.md) (code rules), [WORKFLOW.md](WORKFLOW.md)
(who does what, when).

This README is the **complete install-to-running guide**: prerequisites, the
Python environment, the Docker store, the test suite, the federation, the web portals,
and the Wireshark traffic-capture verification. Deep detail for the federation
and the portals lives in [deploy/README.md](deploy/README.md) and
[portal/README.md](portal/README.md); this page is enough to go start to finish.

---

## 0. Prerequisites

Install these once. `pip` cannot install the last two.

| Tool | Version | Needed for | Verify |
|---|---|---|---|
| **Python** | 3.11 (what CI and the image use) | everything | `python --version` |
| **Docker Desktop** | any recent | the Compose deployment: store, federation, portals | `docker --version` |
| **Wireshark / tshark** | any recent | traffic-analysis module (P4-6/P5-5) | `tshark --version` |

- **Python** — [python.org/downloads](https://www.python.org/downloads/). On
  Windows tick *"Add python.exe to PATH"* during install. The pinned
  requirements have no wheels for Python 3.14 yet; if that is your system
  Python, create the venv with 3.11 instead (`uv venv --python 3.11 .venv`
  with [uv](https://docs.astral.sh/uv/), or `py -3.11 -m venv .venv`).
- **Docker Desktop** — [docker.com](https://www.docker.com/products/docker-desktop/).
  It must be **running** before any `docker` command below. `docker info` should
  succeed.
- **Wireshark** — [wireshark.org/download](https://www.wireshark.org/download.html).
  Install the bundled **Npcap** (Windows) or **libpcap** (Linux/macOS) and, on
  Npcap's setup screen, tick **"Support loopback traffic capture"** — the
  federation talks over loopback, so without it there is nothing to capture.
  `import pyshark` succeeding does **not** mean capture works; only
  `tshark --version` resolving on `PATH` does. On Windows the installer does
  not add Wireshark to `PATH`; prepend it per terminal with
  `$env:PATH="C:\Program Files\Wireshark;$env:PATH"`.

Only the traffic-capture step needs Wireshark; everything else runs without it.
The unit tests run without Docker (the Postgres-backed tests skip cleanly when
no database is reachable); the federation and the portals run only through
Docker Compose.

---

## 1. Python environment

From the repository root:

```bash
python -m venv .venv
```

Activate it — **Windows PowerShell**:

```powershell
.venv\Scripts\Activate.ps1
```

If PowerShell refuses with "running scripts is disabled on this system",
either allow scripts for this window only
(`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`) or skip
activation and call `.venv\Scripts\python.exe` directly.

**Windows:** also set `$env:PYTHONUTF8="1"` in each terminal. The scenario and
demo print non-ASCII marks, and when their output is piped (to a file, or by
`wire.capture`) Python's default cp1252 encoding crashes them.

**macOS / Linux**:

```bash
source .venv/bin/activate
```

Install everything. The dev file pulls in `requirements.txt` and installs the
project itself in editable mode (`-e .`) so bare-name imports resolve
everywhere:

```bash
pip install -r requirements-dev.txt
```

---

## 2. The shared store (Docker Compose)

The shared encrypted store (C4) is PostgreSQL (ADR-0014 / ADR-0020). There is
one way to run it: the `store` service of the Docker Compose deployment in
`deploy/docker-compose.yml`. It listens on host port **55433** (loopback only)
and needs a password. Create `deploy/.env` once; it is git-ignored and Compose
refuses to start without it:

```powershell
python -c "import secrets, pathlib; pathlib.Path('deploy/.env').write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(16) + '\n')"
```

The store lives in tmpfs, so it starts empty whenever its container starts.
Schema migrations run as part of the stack (the `migrate` service), so there is
nothing to apply by hand.

> **Windows tip:** prefer `127.0.0.1` over `localhost` in a DSN. The IPv6
> fallback (`::1`) can add ~10 s per connection.

---

## 3. Run the tests

**Quick, no database** (same scope as the CI `lint` / `format` jobs plus the
Postgres-skipping suite):

```bash
pytest
ruff check src/ tests/ deploy/ wire/ bench/ demo/
black --check src/ tests/ deploy/ wire/ bench/ demo/
```

The storage / audit / deploy / demo suites need PostgreSQL and **skip cleanly
without it**, so a fresh clone still runs green.

**Full, with PostgreSQL** (what the CI `test` job runs; nothing skips). The
tests **drop and recreate the `public` schema** of whatever database
`DATABASE_URL` names, so never point them at the demo's `ehr` database. Give
them a database of their own inside the same Compose store:

```powershell
docker compose -f deploy/docker-compose.yml up -d store
docker compose -f deploy/docker-compose.yml exec store psql -U postgres -c "CREATE DATABASE ehr_test"
$pw = (Get-Content deploy/.env).Split("=",2)[1]
$env:DATABASE_URL = "postgresql://postgres:$pw@127.0.0.1:55433/ehr_test"
pytest tests/ -ra -q
```

(`CREATE DATABASE` fails harmlessly with "already exists" on a second run.) This
runs the real read/write round-trips, the standalone-federation demo
integration, and the cross-facility break-glass end-to-end test over real
sockets. Expected: the whole suite passes (on 2026-10-19: **950 passed** with
Postgres; `tests/wire/test_live_capture.py` also runs once `wire/captures/`
holds fresh captures, and the two missing-`dumpcap` tests skip when Wireshark
is installed).

The Django portals have their own suite (SQLite, no services), see
[portal/README.md](portal/README.md):

```bash
cd portal && python manage.py test --settings=config.test_settings
```

---

## 4. Run the federation (services only)

The deployment is `deploy/docker-compose.yml`. It brings up all **six**
processes (two facilities `facility-a` / `facility-b`, two attribute
authorities `authority-med` / `authority-net`, the `audit` service, and the
portals' key agent `custodian`, ADR-0043) plus the store, the migrations and the
bootstrap sequence of ARCHITECTURE.md §7. Full detail and the port map are in
[deploy/README.md](deploy/README.md).

Create the store password once (step 2), then:

```powershell
docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml logs -f bootstrap
```

Compose runs migrations and bootstrap (seven steps, audit chain verified from
genesis), serves the six roles at `8001/8002/8010/8011/8020/8030`, and starts
the three portals at **http://127.0.0.1:8000/**. All published ports bind to
loopback. It is ready when the log prints `federation is up.` and the
`bootstrap` container has exited 0. Check with
`docker compose -f deploy/docker-compose.yml ps -a`.

After a key-service restart or a failed bootstrap, recreate the disposable demo
with `down` followed by `up --build -d`; this resets its synthetic records. Set
`SEED_DATA=false` only when a driver seeds its own records (for example
`python -m deploy.run_scenario`, which fails with a 500 on `rec-001` if
bootstrap already seeded it). See [deploy/README.md](deploy/README.md) for
verified TLS and recovery details.

To stop it: `docker compose -f deploy/docker-compose.yml down`.

---

## 5. Run the web portals (the website), from scratch

Three role-based Django portals: **patient** (`/patient/`), **clinician**
(`/clinician/`), **admin & audit** (`/oversight/`), on the *Custos* design.
They identify users and show data; they **never** decide access, decrypt, or
hold a key (ADR-0014 / ADR-0021). Anything needing a key goes to the Key
Custodian by `subject_id` after login (ADR-0043).

They are part of the Compose stack, so there is nothing else to install: Docker
Desktop and a clone of the repository are enough. From the repository root, in
PowerShell, with Docker Desktop **running** (`docker info` succeeds):

```powershell
# 1. Store password, first time only (skip if deploy/.env exists)
python -c "import secrets, pathlib; pathlib.Path('deploy/.env').write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(16) + '\n')"

# 2. Start from a clean slate so the synthetic data is fresh and fully seeded
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml up --build -d

# 3. Wait for "federation is up.", then Ctrl+C to leave the log view
docker compose -f deploy/docker-compose.yml logs -f bootstrap

# 4. Check health: services healthy, bootstrap and migrate exited (0)
docker compose -f deploy/docker-compose.yml ps -a
```

Bash / macOS / Linux: the same `docker compose` lines work unchanged; create
`deploy/.env` with the same `python -c` command.

Then open **http://127.0.0.1:8000/**. Password `demo1234` for every login
(synthetic, dev-only):

| user | role | portal | subject |
|---|---|---|---|
| `alice`, `david`, `emma` | patient | `/patient/` | `pat-101`, `pat-102`, `pat-103` |
| `house`, `chase`, `cameron` | clinician | `/clinician/` | `doc-201`, `doc-301`, `doc-202` |
| `auditor` | admin & audit | `/oversight/` | `admin-1` |

Stop it with `docker compose -f deploy/docker-compose.yml down`. Re-create it
(`down`, then `up --build -d`) right before a demo so the records are fresh. Do
not run `deploy.run_scenario` against it before a demo: that driver leaves
records in the emergency-open state. A short step-by-step version with a
troubleshooting table is in [docs/run-portal-docker.md](docs/run-portal-docker.md).
The examiner walk-through (identify, discovery, break-glass, countdown,
dead-token search; patient self-read and upload; admin trace) is in
[portal/README.md](portal/README.md).

### Portal settings

The portal reads these from the environment (defaults shown; every URL comes
from config, never from a request, CONVENTIONS.md §2 rule 8). Compose sets them
for you; this is the reference if you change them in `deploy/docker-compose.yml`.

| Variable | Default | Purpose |
|---|---|---|
| `CUSTODIAN_URL` | `http://127.0.0.1:8030` | key agent: signs / reads / break-glass on the subject's behalf |
| `AUDIT_SERVICE_URL` | `http://127.0.0.1:8020` | append portal events, read chain state |
| `FACILITY_URLS` | `facility-a=http://127.0.0.1:8001,facility-b=http://127.0.0.1:8002` | facility nodes (grant submit, discovery, search) |
| `AUTHORITY_URLS` | `authority-med=http://127.0.0.1:8010,authority-net=http://127.0.0.1:8011` | attribute authorities |
| `SERVICE_TIMEOUT_SECONDS` | `8` | upstream HTTP timeout |
| `EMERGENCY_DURATION_SECONDS` | `14400` | four-hour break-glass window; set 60-120 explicitly for a timer demo (ADR-0060) |
| `STORE_DB_USER` / `STORE_DB_PASSWORD` | `portal_ro` / *(empty)* | **read-only** window onto the store tables |
| `DJANGO_SECRET_KEY` | random per start | set a fixed value in any real deployment |
| `DJANGO_DEBUG` | `0` | Compose runs with debug off; `DJANGO_ALLOWED_HOSTS` defaults to `127.0.0.1,localhost` |
| `PORTAL_PRODUCT_NAME` | `CUSTOS` | name shown in the UI |

The `store` alias connects as `portal_ro`, which has `SELECT` only on the store
tables (`portal/sql/roles.sql`): the ADR-0014 boundary enforced as a Postgres
permission. Compose creates that role for you.

---

## 6. Traffic capture & verification (Wireshark, P4-6)

The required course module (PROJECT.md §4A) records the federation's wire
traffic and asserts wire-level properties. Needs `tshark`/`dumpcap` on `PATH`
(step 0) and, on Windows, the Npcap loopback adapter. **Capture only our own
loopback federation — never a shared or third-party network** (CLAUDE.md).

Generate the local TLS server certs (for the `capture-tls` profile; written to
the git-ignored `wire/certs/`):

```bash
python -m wire.tls
```

Start the federation (step 4, with `SEED_DATA=false` so the scenario seeds its own records) in one terminal. In another, capture each
mode — `wire.capture` drives the break-glass scenario under `dumpcap` and writes
the pcap:

```bash
python -m wire.capture --mode plain --out wire/captures/plain.pcap
```

For the TLS profile, run the federation with TLS enabled (Compose with
`TLS_ENABLED=true docker compose -f deploy/docker-compose.yml up --build -d`
after `python -m wire.tls`), then:

```bash
CAPTURE_TLS=true TLS_ENABLED=true python -m wire.capture --mode tls --out wire/captures/tls.pcap
```

Analyse both captures (the P5-5 wire-level checks):

```bash
python -m wire.analyze_traffic --captures wire/captures
```

> On Windows, `dumpcap` may not auto-detect loopback — pass the Npcap loopback
> adapter explicitly, e.g. `--interface "\Device\NPF_Loopback"`. List adapters
> with `tshark -D`.

Done when both modes produce a capture file and the analyzer's checks pass.

---

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
