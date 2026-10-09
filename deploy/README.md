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

From the repository root, create a store password once. It goes in
`deploy/.env`, which is git-ignored and kept out of the image build context.
Compose refuses to start without it:

```bash
python -c "import secrets, pathlib; pathlib.Path('deploy/.env').write_text('POSTGRES_PASSWORD=' + secrets.token_urlsafe(16) + '
')"
```

Then:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Compose brings up Postgres (`store`), the six application services, the portal, and a
one-shot `bootstrap` container that runs once every other service reports
healthy. The store lives in tmpfs, so it starts empty whenever its container
starts (same reason as Path A's reset); re-running `up` on a running stack
leaves it alone. Watch the bootstrap logs for the same step-by-step output as
Path A:

```bash
docker compose -f deploy/docker-compose.yml logs -f bootstrap
```

Look at the database (published on host port 55433, loopback only, password
from `deploy/.env`):

```bash
docker compose -f deploy/docker-compose.yml exec store psql -U postgres -d ehr
```

The three portals start automatically at **http://127.0.0.1:8000/**, with the
same logins as the portal demo. To run a portal separately against a services-only
stack (start Compose with `up --build bootstrap`):

```bash
DATABASE_URL=postgresql://postgres:<POSTGRES_PASSWORD>@127.0.0.1:55433/ehr python -m deploy.seed_portal
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
encryption (`crypto_core`/`records`/`pre`), not from transport security. The verified
TLS profile is described below.

## TLS (verified certificates)

Generate the local certificates before starting the TLS profile:

```powershell
python -m wire.tls
$env:TLS_ENABLED="true"
docker compose -f deploy/docker-compose.yml up --build -d
```

All federation clients, including bootstrap and the portal, use HTTPS and trust
`wire/certs/trust/ca-bundle.crt`. Each container mounts only its own
`wire/certs/<service>/` key directory plus that bundle. No `TLS_VERIFY=false` is needed. The browser portal
itself stays at HTTP on loopback. To return to plain HTTP, tear down the TLS stack,
remove `TLS_ENABLED`, and start again. Do not regenerate certificates while the
TLS stack is running.

Path A also supports `TLS_ENABLED=true` after certificate generation. Run the
scenario with `python -m deploy.run_scenario --scheme https`; it uses the same
trust bundle. As before, start a fresh federation with `SEED_DATA=false` when
using a scenario/driver that seeds its own records.

## Restarts and recovery

Compiled policies and signed consent artifacts are shared through PostgreSQL,
so routine cross-facility reads now return a real policy decision. Private keys,
emergency sessions and replay caches remain in process memory by design.

A successful bootstrap records the live service instance IDs only after seeding
and audit verification finish. Re-running bootstrap on the same live stack
checks those IDs and the audit chain. A partial bootstrap, changed seed mode or
restarted key service is refused with a recovery instruction. Recreate the whole
**disposable demo** (this removes its synthetic data):

```powershell
docker compose -f deploy/docker-compose.yml down
docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml logs bootstrap
```

Restarting only the portal preserves its database tables. The demo publishes
ports only on `127.0.0.1`; its trusted-local custodian API and throwaway database
must not be exposed to a shared network. This setup does not provide persistent
key custody or internet-facing authentication.

The timer now mirrors its audited expiry states into the store automatically.
The existing ADR-0043/0044 limitation remains: rotated ciphertext is not persisted
because the caller supplies a throwaway re-baseline key. Search expiry is enforced;
persisted post-expiry DEK rotation is not demonstrated by this deployment.
