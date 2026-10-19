# 0. Quick startup (Windows / PowerShell)

Get the whole system and the three web portals running in about five minutes.
Run everything from the project root, `D:\Powel\MIT\Projects\secure-federated-health-records`.

**You need:** Docker Desktop running, and the project's virtual environment
(`.venv`) already installed (see the main `README.md` §1 if it is not).

---

## First time only

### 1. Create the Postgres container

```powershell
docker run -d --name p08pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr_test -p 55432:5432 postgres:16-alpine
```

Check that it is up (status must say `Up`):

```powershell
docker ps --filter name=p08pg
```

Port `55432` is used on purpose so it does not clash with any Postgres already on
`5432`.

---

## Every time you run the demo

### 2. Activate the environment and point at the database

```powershell
.venv\Scripts\Activate.ps1
$env:DATABASE_URL="postgresql://postgres@localhost:55432/ehr_test"
```

### 3. Start the federation, custodian and portals

```powershell
python -m deploy.run_portal_demo --duration 60
```

This brings up six processes, seeds the synthetic data, deposits each persona's
key material with the Key Custodian, creates the portal schema, and serves the
portals. Wait for the line:

```
[6/6] starting the portals at http://127.0.0.1:8000/
```

`--duration 60` shortens the emergency (break-glass) window to 60 seconds so a
live audience does not wait. The default is 120 seconds.

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

Press **Ctrl+C** in the terminal. The container keeps running.

---

## Useful variations

| Want to | Command |
|---|---|
| Use another web port | add `--port 8001` and open that port |
| Seed and exit (no server, CI smoke) | add `--no-server` |
| Longer emergency window (paper value) | `--duration 900` |
| Run the unit tests (no stack needed) | `python -m pytest tests -q` |
| Run tests that need Postgres too | `python -m pytest tests -ra -q` (with `DATABASE_URL` set) |
| Run the automated end-to-end checks | `python -m tests.e2e.portal_flows --no-stress` (stack must be running) |
| Run it with the concurrency stress phase | `python -m tests.e2e.portal_flows --workers 4 --iterations 3` |
| Include the expiry check | `python -m tests.e2e.portal_flows --expiry-wait 70` (duration + 10 s) |

> The end-to-end script leaves records in the emergency-open state. **Restart the
> stack (step 3) before a live demo.** Every start resets the data.

---

## Container housekeeping

```powershell
docker stop p08pg          # stop
docker start p08pg         # start again (do this if Docker was restarted)
docker rm -f p08pg         # delete it and all data; then repeat step 1
```

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `No such container: p08pg` | Never created | Do step 1 |
| `port is already allocated` on `55432` | Port in use | Use `-p 55433:5432` and `...@localhost:55433/...` |
| `connection refused` in step 3 | Container not running or not ready | `docker ps`, wait a few seconds, `docker start p08pg` |
| `ModuleNotFoundError: psycopg` / `django` | Wrong Python, not the project venv | Run step 2's `Activate.ps1` first |
| Port 8000 busy | Another server running (or the Compose portal) | `--port 8001`, or stop the other one |
| Compose says `POSTGRES_PASSWORD` is missing | No `deploy/.env` yet | Create it (see Other ways to run) |
| `run_scenario` fails with a 500 on `rec-001` | Bootstrap already seeded that record | Recreate the stack with `SEED_DATA=false` |
| `run_scenario` prints a `charmap` error on Windows | Console encoding | Set `PYTHONUTF8=1` |
| Break-glass says `emergency_open -> emergency_open` | That record is already open this run | Restart the stack, or wait for the time-box to end |
| Portal shows "store error" | Database unreachable | Check `$env:DATABASE_URL` and `docker ps` |

## Other ways to run

- **Federation only, no web portals** (Path A): `python -m deploy.run_local`
  with `DATABASE_URL` set. Prints the service URLs.
- **Docker Compose** (reproducible, brings its own Postgres and the portals).
  Create a store password once, then start it:

  ```powershell
  python -c "import secrets, pathlib; pathlib.Path('deploy/.env').write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(16) + '\n')"
  docker compose -f deploy/docker-compose.yml up --build -d
  docker compose -f deploy/docker-compose.yml logs bootstrap
  ```

  Portals at http://127.0.0.1:8000/ with the same logins. All ports bind to
  loopback only; the store is on `55433`. Keys live only in process memory, so
  after a key-service restart or a failed bootstrap, `down` then `up --build -d`
  (this resets the synthetic data). Bootstrap refuses a partial or stale rerun
  and says so. Full details: `deploy/README.md`.
- **Verified TLS between services:** `python -m wire.tls`, then
  `$env:TLS_ENABLED="true"` before either path. Generated certificates are
  trusted explicitly; verification is never switched off.
- **Wireshark capture** (Phase 5 module): see `README.md` §6 and
  [06-traffic-analysis-module.md](06-traffic-analysis-module.md).
