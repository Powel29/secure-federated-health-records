# Web portals (C16) — patient / clinician / admin & audit

Three role-based Django portals over one cryptographic core, styled on the
**Custos** design system (`static/portal/custos.css`). **Boundary
(ADR-0014/0021/0043):** the portals identify users and show data; they never
decide access, never decrypt, and never hold a key. Anything that needs a key
goes to the **Key Custodian** service (`src/api/custodian_service.py`) by
`subject_id` after login; the facility's policy engine, the audit service's
commit-before-release and the facility's grant-signature check still decide.

| Portal | Path | What it does |
|---|---|---|
| Patient | `/patient/` | alerts (break-glass, revocation, incoming requests); approve / deny / revoke consent (signed by the custodian as the patient, verified by the facility); access history straight from the hash chain; own records decrypted through the `owner:<patient_id>` leaf for one request only; **upload** a record of their own (sealed by the facility under a chosen clinical policy + the owner leaf, emergency key split 2-of-3) |
| Clinician | `/clinician/` | identify a patient by name + DOB (ADR-0033; every lookup logged first); request consent; read under a grant; federated discovery; declare break-glass (assertion bound to the identified id); live countdown, three-share panel, chain segment, emergency search |
| Admin & audit | `/oversight/` | trace any flow by correlation id with link checks and genesis verification; break-glass case review; federation process health, store contents, trust topology; registrations (read-only; issuance stays the authority's) |

---

## Quick check: the tests (no Postgres, no services)

```
cd portal
python manage.py test --settings=config.test_settings
```

In-memory SQLite with every service call mocked at `portal_core.services`.
36 tests, including the fail-closed evidence: a login with no key-agent
material decrypts nothing; a patient without the owner attribute is refused;
a lookup that cannot be logged shows no candidates; a failed break-glass is a
"failed closed" case with no notification.

## Run everything with one command

Needs a reachable PostgreSQL and the repo installed (`pip install -e .` or
`PYTHONPATH=src`). Any database works — the schema is reset each run.

```bash
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/mydb python -m deploy.run_portal_demo
```

That starts the five federation services and the custodian as separate
processes on the fixed ports (`--in-process` runs them as threads instead), seeds
the synthetic dataset (P4-5) and deposits each persona's key material, creates
the `portal` schema and the read-only `portal_ro` store role, migrates Django,
seeds the logins + patient directory, and serves the portals at
http://127.0.0.1:8000/. `--duration 60` shortens the break-glass time-box for
a live demo; `--no-server` seeds and exits (CI smoke). Use `127.0.0.1`, not
`localhost`, in the DSN on Windows (IPv6 fallback costs ten seconds per
connection).

Logins (password `demo1234` for all — synthetic, dev-only):

| user | role | subject |
|---|---|---|
| `alice`, `david`, `emma` | patient | `pat-101`, `pat-102`, `pat-103` |
| `house` (ER, facility-b), `chase` (cardiology, facility-a), `cameron` (endocrinology, facility-b) | clinician | `doc-201`, `doc-301`, `doc-202` |
| `auditor` | admin & audit | `admin-1` |

A namesake **Alice Vance / 1982-04-15 / `pat-777`** with no records is seeded
so the identification step shows an ambiguous match the clinician must choose
from.

**The examiner walk-through.** Log in as `house` → *Identify patient* (Vance,
1982-04-15) → pick `pat-101` → *Run federated discovery* → choose `rec-001`,
a reason code → *Sign assertion and request shares*. The session page shows
shares 1 + 3, the chain seq the audit service committed **before** releasing
share 3, the decrypted record (once), a live countdown and the chain segment;
search while the token lives, then again after expiry. Log in as `alice` to
see the alert, the history, to open her own record via the owner leaf, and to
*Upload a record* (any PDF/image/JSON/text) that then behaves exactly like a
seeded one — readable by her, by the chosen specialty, and by break-glass.
Log in as `auditor` and paste the correlation id into *Trace*.

## Run against a separately deployed federation

Path A (`python -m deploy.run_local`) and Path B (`docker compose -f
deploy/docker-compose.yml up`) both start the custodian on port 8030 and seed
it. Then one command creates the portal schema, the logins and the patient
directory, and serves the portals:

```bash
DATABASE_URL=postgresql://postgres:<POSTGRES_PASSWORD>@127.0.0.1:55433/ehr python -m deploy.seed_portal
```

(Path B's store is on 55433; for Path A use its own `DATABASE_URL`.) The
portal finds the services through these environment variables:

| variable | default |
|---|---|
| `CUSTODIAN_URL` | `http://127.0.0.1:8030` |
| `AUDIT_SERVICE_URL` | `http://127.0.0.1:8020` |
| `FACILITY_URLS` | `facility-a=http://127.0.0.1:8001,facility-b=http://127.0.0.1:8002` |
| `AUTHORITY_URLS` | `authority-med=http://127.0.0.1:8010,authority-net=http://127.0.0.1:8011` |
| `EMERGENCY_DURATION_SECONDS` | `120` |
| `PORTAL_DB_HOST/PORT/NAME/USER/PASSWORD` | `localhost` / `55432` / `ehr_test` / `postgres` / `` |
| `STORE_DB_USER/PASSWORD` | `portal_ro` / `` |

Then `python portal/manage.py migrate` and `python portal/manage.py runserver`.
The `store` alias connects as `portal_ro`, which has SELECT only on the store
tables (`sql/roles.sql`) — the ADR-0014 boundary as a Postgres permission.

## What the portal writes, and where

- **Its own schema only** (`portal`): logins, profiles, the patient directory
  (the only PII, ADR-0033), the consent ledger (signed public artifacts, a
  display mirror of what the facility verified), break-glass case files, and
  patient notifications.
- **The audit chain, through the audit service's `POST /entries`:**
  `patient.lookup`, `patient.notification`, `consent.decision`. Identifiers and
  hashes only.
- **Never the store.** Records, wrappings, transitions and the chain itself are
  written only by the federation services.

Not in the strict `src/` lint/format scope (Django has its own idioms). CI runs
the portal tests on SQLite (`portal` job).
