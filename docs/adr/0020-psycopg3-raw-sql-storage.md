# ADR-0020: psycopg3 + raw SQL migrations for the store (no ORM)

- **Status:** Accepted
- **Date:** 2026-08-21
- **Deciders:** Avaneeth (P0-8 owner), confirmed with the team
- **Task / source:** P0-8 (WORKFLOW.md); ARCHITECTURE §2 C4, §7; ADR-0014
- **Affects:** `storage` (C4), `requirements.txt`, CI (`.github/workflows/ci.yml`)

## Context

P0-8 builds the PostgreSQL schema for the shared store, and the project had **no**
database library yet. So P0-8 had to pick both a driver/access layer and a
migration approach. The store's job is narrow and fixed (ADR-0014/0011): persist
ciphertext, wrapped keys, and identifiers across ~10 stable tables; never decide
access, never decrypt. CONVENTIONS §2 rule 7 forbids string-built SQL.

## Decision

- **Driver / access layer: `psycopg[binary]==3.2.9`, raw parameterised SQL** in
  thin repository functions. No ORM, no query builder.
- **Migrations: numbered `.sql` files** (`src/storage/migrations/NNNN_*.sql`)
  applied by a small runner (`storage/migrate.py`) that records applied files in
  a `schema_migrations` table and is idempotent (re-run is a no-op).
- **Schema mirrors the frozen contracts** (identifiers → `text`, crypto material
  → `bytea`, timestamps → `timestamptz`, enums → `text` + `CHECK`); storage-only
  tables without a contract (`search_index`, `lifecycle_state`, `attributes`) are
  built minimally and flagged for refinement when their owning modules land.

## Consequences

- Every query is visible, auditable, and parameterised — easy to check against
  rule 7 (ruff S608 also guards it) and against "the store never decides access."
- No ORM magic to reason about; the repository layer is ~ten insert/fetch pairs.
- **Tests need a real Postgres.** A `conftest` skips the storage suite cleanly
  when `DATABASE_URL` is unset, so a clone without Postgres still runs the rest of
  the suite; CI provides Postgres via a service container so the round-trips
  actually run on every PR.
- **Downside:** the schema is Postgres-specific SQL, so storage tests cannot run
  against an in-memory SQLite substitute — a live Postgres is required to
  exercise them. Accepted: it is one `docker run` locally and a service block in
  CI, and it keeps the SQL honest (real CHECKs, `bytea`, `jsonb`, `uuid`).
- Hand-written migrations must be edited carefully once shipped; the runner does
  not diff models against the DB the way Alembic would.

## Alternatives considered

- **SQLAlchemy Core + Alembic.** Rejected: heavier dependency and more moving
  parts than a fixed 10-table schema needs; its main upside (SQLite for unit
  tests) is modest, and it adds a layer between the code and the SQL we want to
  audit directly.
- **SQLAlchemy ORM.** Rejected: most magic, hardest to audit against the crypto
  rules, and it couples persistence to Python objects for no benefit here.
