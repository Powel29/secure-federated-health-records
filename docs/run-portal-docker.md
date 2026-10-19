# Run the portal with Docker (end to end)

Tested and working. Run everything from the repository root in PowerShell.
Docker Desktop must be running first (`docker info` should succeed).

## 1. Create the store password (first time only)

Compose refuses to start without it. The file is git-ignored. If `deploy/.env`
already exists, skip this step.

```powershell
python -c "import secrets, pathlib; pathlib.Path('deploy/.env').write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(16) + '\n')"
```

## 2. Start from a clean slate

`down` first so the synthetic data is fresh and fully seeded.

```powershell
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml up --build -d
```

## 3. Wait until it is ready

Wait for the line `federation is up.`, then press Ctrl+C to leave the log view.

```powershell
docker compose -f deploy/docker-compose.yml logs -f bootstrap
```

## 4. Check that everything is healthy

All services should say healthy. `bootstrap` and `migrate` should say exited (0).

```powershell
docker compose -f deploy/docker-compose.yml ps -a
```

## 5. Open the portal

http://127.0.0.1:8000/ , password `demo1234` for every login.

| Portal | URL | Log in as |
|---|---|---|
| Patient | `/patient/` | `david` (or `alice`, `emma`) |
| Clinician | `/clinician/` | `house` (or `cameron`, `chase`) |
| Admin and audit | `/oversight/` | `auditor` |

## 6. Stop it

```powershell
docker compose -f deploy/docker-compose.yml down
```

---

## Before a demo

- Run step 2 again (`down`, then `up --build -d`) shortly before you present, so
  no record is left in a stale state.
- Do not run `python -m deploy.run_scenario` against this stack beforehand. It
  needs the stack started with `SEED_DATA=false` and leaves records in the
  emergency-open state.
- Do not set `SEED_DATA=false` if you want the portal logins above. Without
  seeding there are no demo users.

## Useful commands

Logs for one service:

```powershell
docker compose -f deploy/docker-compose.yml logs -f portal
docker compose -f deploy/docker-compose.yml logs facility-a
```

Look inside the database (it asks for the password stored in `deploy/.env`):

```powershell
docker compose -f deploy/docker-compose.yml exec store psql -U postgres -d ehr
```

Verified TLS profile (optional):

```powershell
python -m wire.tls
$env:TLS_ENABLED="true"
docker compose -f deploy/docker-compose.yml up --build -d
```

## Ports (all on 127.0.0.1 only)

| Port | Service |
|---|---|
| 8000 | Portals (patient, clinician, admin) |
| 8001 / 8002 | Facility A / Facility B |
| 8010 / 8011 | Authority med / Authority net |
| 8020 | Audit service |
| 8030 | Key custodian |
| 55433 | Postgres |

## If something goes wrong

| Symptom | Cause | Fix |
|---|---|---|
| `POSTGRES_PASSWORD` is missing | No `deploy/.env` | Do step 1 |
| Cannot connect to the Docker engine | Docker Desktop is not running | Start Docker Desktop, wait, retry |
| Page at port 8000 does not load | Bootstrap did not finish | `docker compose -f deploy/docker-compose.yml logs bootstrap` and `... logs portal` |
| Port already in use | Another program on 8000 to 8030 or 55433 | Stop it, or run `down` for an older stack |
| Login fails | Stack was started with `SEED_DATA=false` | Run step 2 again without it |
| Stack in a strange state | Partial or stale run | `down`, then `up --build -d` (resets all synthetic data) |

This path does not use the `p08pg` container. Compose brings its own Postgres.
