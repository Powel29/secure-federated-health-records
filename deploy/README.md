# Running the federation

Two ways to bring up all six processes (`store`, `facility-a`, `facility-b`,
`authority-med`, `authority-net`, `audit`) — see `ARCHITECTURE.md` §7 for the
full topology and bootstrap-sequence rationale, and ADR-0039 for the
implementation decisions behind what's here.

Both paths run the same bootstrap sequence (`deploy/bootstrap.py`): apply
migrations, generate the federation PKI (root anchor + facility CAs), start
the authorities and register their certificates with the root, start the
audit service, start the facility nodes, then verify the audit chain from
genesis before declaring success. **If that last check fails, nothing else
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

This prints each bootstrap step as it happens, then the five services' URLs.
Press Ctrl+C to stop everything together.

## Path B — Docker Compose

From the repository root:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Compose brings up Postgres (`store`), the five application services, and a
one-shot `bootstrap` container that runs once every other service reports
healthy. Watch its logs for the same step-by-step output as Path A:

```bash
docker compose -f deploy/docker-compose.yml logs -f bootstrap
```

Tear down (including the named Postgres volume):

```bash
docker compose -f deploy/docker-compose.yml down -v
```

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

## What this does not do

Seeding synthetic patient data and running the demo scenario is P4-5's job
(the demo driver), not the bootstrap sequence's — bootstrap only proves the
federation's trust and audit machinery are correctly wired, with nothing
patient-specific in it yet.
