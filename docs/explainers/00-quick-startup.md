# 0. Quick startup (Windows / PowerShell)

Get the whole system and the three web portals running in about five minutes.
Run everything from the project root, `D:\Powel\MIT\Projects\secure-federated-health-records`.

**You need:** Docker Desktop running (`docker info` succeeds). That is all for the
demo: the portals, the federation and the Postgres store all run in containers
from `deploy/docker-compose.yml`. The `.venv` (main `README.md` §1) is only
needed to run the tests or the drivers.

---

## First time only

### 1. Create the store password

Compose refuses to start without it. The file is git-ignored.

```powershell
python -c "import secrets, pathlib; pathlib.Path('deploy/.env').write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(16) + '\n')"
```

---

## Every time you run the demo

### 2. Start from a clean slate

```powershell
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml up --build -d
```

### 3. Wait until it is ready

```powershell
docker compose -f deploy/docker-compose.yml logs -f bootstrap
```

Wait for `federation is up.`, then press Ctrl+C to leave the log view. Check
`docker compose -f deploy/docker-compose.yml ps -a`: services healthy,
`bootstrap` and `migrate` exited (0).

### 4. Open the portals

http://127.0.0.1:8000/ — log in with password `demo1234` for every user.

| User | Portal | Subject | Notes |
|---|---|---|---|
| `alice` | patient | `pat-101` | owns `rec-001` (cardiology) |
| `david` | patient | `pat-102` | owns `rec-002` (endocrinology) |
| `emma` | patient | `pat-103` | owns `rec-003` |
| `house` | clinician | `doc-201` | emergency physician, facility-b |
| `chase` | clinician | `doc-301` | cardiologist, facility-a |
| `cameron` | clinician | `doc-202` | endocrinologist, facility-b |
| `auditor` | admin / audit | `admin-1` | read-only chain view |

Direct URLs: `/patient/`, `/clinician/`, `/oversight/`.

### 5. Stop

```powershell
docker compose -f deploy/docker-compose.yml down
```

---

## Useful variations

| Want to | Command |
|---|---|
| Run the unit tests (no stack needed) | `python -m pytest tests -q` |
| Run tests that need Postgres too | see `README.md` §3 (a separate `ehr_test` database in the Compose store) |
| Seed nothing (a driver seeds its own records) | `$env:SEED_DATA="false"` before `up --build -d` |
| Short emergency window for a demo (default is 4 h = `14400`; a window can be shortened, never extended) | `$env:EMERGENCY_DURATION_SECONDS="60"` before `up --build -d` |
| Verified TLS between services | `python -m wire.tls`, then `$env:TLS_ENABLED="true"` before `up --build -d` |
| Wireshark capture (Phase 5 module) | `README.md` §6 and [06-traffic-analysis-module.md](06-traffic-analysis-module.md) |

> The end-to-end script and `deploy.run_scenario` leave records in the
> emergency-open state. **Recreate the stack (steps 2–3) before a live demo.**
> Every start resets the data.

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| Compose says `POSTGRES_PASSWORD` is missing | No `deploy/.env` yet | Do step 1 |
| Cannot connect to the Docker engine | Docker Desktop is not running | Start it, wait, retry |
| Page at port 8000 does not load | Bootstrap did not finish | `docker compose -f deploy/docker-compose.yml logs bootstrap` and `... logs portal` |
| Port already in use | Another program on 8000–8030 or 55433 | Stop it, or `down` an older stack |
| Login fails | Stack was started with `SEED_DATA=false` | Recreate it without that setting |
| `run_scenario` fails with a 500 on `rec-001` | Bootstrap already seeded that record | Recreate the stack with `SEED_DATA=false` |
| `run_scenario` prints a `charmap` error on Windows | Console encoding | Set `PYTHONUTF8=1` |
| Break-glass says `emergency_open -> emergency_open` | That record is already open this run (a second *open* is illegal; a *join* by another clinician of the opening facility is allowed) | Recreate the stack, or wait for the time-box to end |
| Stack in a strange state | Partial or stale run | `down`, then `up --build -d` (resets all synthetic data) |

Keys live only in process memory (paper limitations 5 and 8: the custodian and the
audit service lose their shares on restart), so after a key-service restart or a
failed bootstrap, `down` then `up --build -d`. Bootstrap refuses a partial or stale
rerun and says so. Full details: `deploy/README.md`.
