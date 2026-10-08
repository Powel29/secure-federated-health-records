# Running the federation

Two ways to bring up all seven processes (`store`, `facility-a`, `facility-b`,
`authority-med`, `authority-net`, `audit`, and the portals' key agent
`custodian`, ADR-0043) — see `ARCHITECTURE.md` §7 for the full topology and
bootstrap-sequence rationale, and ADR-0039 for the implementation decisions
behind what's here.

**Want the browser demo?** `python -m deploy.run_portal_demo` (with
`DATABASE_URL` set) runs everything below *plus* the seeded dataset, the key
deposits and the three Django portals in one process — see `portal/README.md`.
The two paths here are the multi-process deployments the phase exit criteria
and the traffic-capture module need.

Both paths run the same bootstrap sequence (`deploy/bootstrap.py`): apply
migrations, generate the federation PKI (root anchor + facility CAs), start
the authorities and register their certificates with the root, start the
audit service, start the facility nodes, record the authorities, facilities
and synthetic patient ids in the store, seed the synthetic dataset (three
records) and deposit its key material with the custodian, then verify the
audit chain from genesis before declaring success. **If that last check fails, nothing else
is considered up** (ARCHITECTURE.md §7).

## Path A — local processes (no Docker)

Needs a reachable PostgreSQL. If you don't have one, a throwaway instance
(see the top-level `README.md` "Database (PostgreSQL)" section):

```bash
docker run -d --name p08pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr_local -p 55432:5432 postgres:16-alpine
```

Then, from the repository root:

```bash
DATABASE_URL="postgresql://postgres@localhost:55432/ehr_local" python -m deploy.run_local
```

This prints each bootstrap step as it happens, then the six services' URLs
(the custodian on 8030 last). Press Ctrl+C to stop everything together.
Each run resets the database's `public` schema first: every service keeps
its keys in memory, so a previous run's data is unreadable anyway.

## Path B — Docker Compose

From the repository root:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Compose brings up Postgres (`store`), the six application services, and a
one-shot `bootstrap` container that runs once every other service reports
healthy. The store lives in tmpfs, so it starts empty whenever its container
starts (same reason as Path A's reset); re-running `up` on a running stack
leaves it alone. Watch the bootstrap logs for the same step-by-step output as
Path A:

```bash
docker compose -f deploy/docker-compose.yml logs -f bootstrap
```

Look at the database (published on host port 55433):

```bash
docker compose -f deploy/docker-compose.yml exec store psql -U postgres -d ehr
```

Run the three portals against it (http://127.0.0.1:8000/, same logins as the
portal demo):

```bash
DATABASE_URL=postgresql://postgres@127.0.0.1:55433/ehr python -m deploy.seed_portal
```

Tear down:

```bash
docker compose -f deploy/docker-compose.yml down
```

`SEED_DATA=false` (either path) skips the seeding, for drivers that seed the
same dataset themselves (`python -m demo.driver`, `python -m
deploy.run_scenario`); the authorities, facilities and patient ids are still
registered.

## What gets written where

Both paths write `deploy/pki/federation.json` (Path B via a bind-mounted
volume) — the root certificate, each facility's CA certificate *and private
key* (needed downstream to issue clinician certificates), and each
authority's certificate and endpoint. This directory is `.gitignore`d in its
entirety (WORKFLOW.md §4) — **never commit anything under it**, including
between runs; every run regenerates it from scratch.

## Traffic capture

Inter-service traffic is plain HTTP by default — this *is* the
`capture-plain` profile `PROJECT.md` §4A's traffic-analysis module captures
against, deliberately: confidentiality here comes from the application-layer
encryption (`crypto_core`/`records`/`pre`), not from transport security. A
TLS variant (`capture-tls`, defence-in-depth) is P4-6's addition, not this
one's.

## Known limitation

Facility nodes keep compiled policies in process memory
(`api.repository.PostgresStorageRepository`), so a *routine* read at a
facility other than the one that ingested the record returns 500 here
instead of a policy decision. Break-glass is unaffected. `deploy.run_scenario`
and the demo driver's out-of-network refusal step hit this; their in-process
runs (`--standalone`, `tests/deploy`) share one process and do not.
