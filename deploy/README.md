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
PGPASSWORD=<POSTGRES_PASSWORD> DATABASE_URL=postgresql://postgres@127.0.0.1:55433/ehr python -m deploy.seed_portal
```

Tear down:

```bash
docker compose -f deploy/docker-compose.yml down
```

`SEED_DATA=false` (either path) skips the seeding, for drivers that seed the
same dataset themselves (`python -m demo.driver`, `python -m
deploy.run_scenario`); the authorities, facilities and patient ids are still
registered.

### Running the scenario against Compose

`python -m deploy.run_scenario` runs on the host and needs two settings that
Path A does not:

- **`SEED_DATA=false`.** The scenario ingests `rec-001`, which the seed data
  already uses. Shares are never overwritten (review F4), so a seeded stack
  answers the scenario's share deposit with 409.
- **The bootstrap identity.** Every service accepts only signed requests
  from a root-certified service (ADR-0066). The `pki` job writes every
  service's key and certificate to `deploy/pki/services/<id>/` (git-ignored);
  the scenario signs as `deploy/pki/services/bootstrap`, so run it from the
  repository root on the machine that ran Compose.

```bash
SEED_DATA=false docker compose -f deploy/docker-compose.yml up --build -d
python -m deploy.run_scenario
```

For the TLS profile, add `TLS_ENABLED=true` to both `up` commands and run the
scenario with `--scheme https`. On Windows, set `PYTHONIOENCODING=utf-8`
first, or the scenario fails while printing its ✓ marks. Recreate the stack
without these variables to return to the seeded default.

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
using a scenario/driver that seeds its own records; under Compose, see
"Running the scenario against Compose" above.

### The store link is TLS too (ADR-0071)

In the TLS profile every connection to Postgres uses `sslmode=verify-full`
against `wire/certs/trust/store.crt` (set by `deploy.config.configure_transport`),
so a store without TLS, or with any other certificate, is refused. A
`DATABASE_URL` carrying a weaker `?sslmode=` is refused too. Compose's `store`
does this itself (`deploy/store-entrypoint.sh`): with `TLS_ENABLED=true` it
serves only TLS 1.3 and its `pg_hba` rejects every non-TLS connection. The
plain profile is unchanged, so P5-5 claim 2 can still read the audit `COMMIT`
off the plain capture.

For Path A, start the throwaway store through the same script (after
`python -m wire.tls`, from the repository root):

```bash
docker run -d --name p08pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr -e TLS_ENABLED=true -p 127.0.0.1:55433:5432 -v "$PWD/wire/certs/store:/tls/store:ro" -v "$PWD/deploy/store-entrypoint.sh:/store-entrypoint.sh:ro" --entrypoint sh postgres:16-alpine /store-entrypoint.sh
```

In Git Bash, prefix it with `MSYS_NO_PATHCONV=1` so the container paths are not
rewritten. Regenerating certificates means restarting the store as well.

## Restarts and recovery

Compiled policies and signed consent artifacts are shared through PostgreSQL,
so routine cross-facility reads now return a real policy decision. Private keys
remain in process memory by design. Open emergency sessions are stored without
their keys, and a restarted facility closes its own with a rotation
(ADR-0081); the facility's one-time ids persist in the store (review F22).

Each facility also keeps the highest audit `seq` it has seen in
`AUDIT_HIGH_WATER_FILE` (ADR-0083), so after a restart it still refuses an
audit chain that was cut back. Under Compose the file lives in the container's
own filesystem and goes away on `down` together with the store; Path A keeps it
in `deploy/pki/state/` and deletes it when it resets the store. If you reset
only the store, delete that file too, or every audit append from that facility
fails with "audit chain went backwards".

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

The timer mirrors its audited expiry states into the store and, at every
expiry, runs the full rotation (ADR-0069): a new DEK, policy root, emergency key
and shares, and a re-derived search index, stored before the record returns to
baseline. The facility needs `AUTHORITY_URLS` and `CUSTODIAN_URL` for that, and
the custodian and audit service accept the new shares only while the store shows
the record `expired`.

Every process has its own service identity (`deploy/pki/services/<id>/`,
ADR-0066), issued fresh with the rest of the PKI on each run. Each Compose
container mounts only its own directory; the keys are owner-only and belong to
the containers' `app` user.
