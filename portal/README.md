# Web portals (C16) — early dev shells (ADR-0021)

Three role-based Django portals (patient / clinician / admin-audit) plus
self-service registration. **Boundary:** the portals identify users and show
data; they never decide access or decrypt. Every crypto action reaches a
`NotWiredYet` stub until its backend lands (`authority` P2-2, ingest P3-14,
breakglass P3-5).

The governing invariant (ADR-0021): **a portal account alone grants zero
access.** A self-registered doctor holds no attribute and can open nothing;
credentials are *issued* by an authority, never by a signup form.

---

## Quick check: run the tests (no Postgres needed)

```
cd portal
python manage.py test --settings=config.test_settings
```

In-memory SQLite; exercises registration and the invariant test
(*a self-registered account is issued no credential*).

---

## Run the live portal

Runs against the P0-8 Postgres store, with Django's own tables in a separate
`portal` schema and a **read-only** `portal_ro` role on the store (the ADR-0014
boundary, enforced by Postgres). **Docker Desktop must be running.**

Run everything from the **repo root**, in your own terminal (VS Code
`Terminal → New Terminal`, or PowerShell/Git Bash `cd`'d to the project).

### One-time setup

| # | Step | PowerShell | Git Bash |
|---|------|-----------|----------|
| 1 | Start Postgres | `docker run -d --name p08pg -e POSTGRES_HOST_AUTH_METHOD=trust -e POSTGRES_DB=ehr_test -p 55432:5432 postgres:16-alpine` | *(same)* |
| 2 | Store tables (P0-8) | `$env:DATABASE_URL="postgresql://postgres@localhost:55432/ehr_test"; .venv\Scripts\python -m storage.migrate` | `DATABASE_URL="postgresql://postgres@localhost:55432/ehr_test" .venv/Scripts/python -m storage.migrate` |
| 3 | `portal` schema + `portal_ro` role | `Get-Content portal\sql\roles.sql \| docker exec -i p08pg psql -U postgres -d ehr_test` | `docker exec -i p08pg psql -U postgres -d ehr_test < portal/sql/roles.sql` |
| 4 | Django tables | `.venv\Scripts\python portal\manage.py migrate` | `.venv/Scripts/python portal/manage.py migrate` |
| 5 | Admin login | `.venv\Scripts\python portal\manage.py createsuperuser` | `.venv/Scripts/python portal/manage.py createsuperuser` |

At step 5, sample **dev-only** credentials (never reuse or commit): username
`admin`, email blank, password `admin1234` (password validators are off in dev).

### Every run

```
.venv\Scripts\python portal\manage.py runserver
```

Leave that window open (Ctrl+C to stop). If the container was only stopped, not
removed, run `docker start p08pg` first; skip steps 2–5.

### Open in the browser — http://localhost:8000

| URL | What |
|---|---|
| `/` | Landing — "Register as patient / clinician" |
| `/accounts/login/` | Log in (e.g. `admin` / `admin1234`) |
| `/oversight/` | Admin/audit portal — reads the store **read-only** |
| `/django-admin/` | Django admin — inspect `Profile` / `RegistrationRequest` |

A superuser has no `Profile`, so `/` won't auto-route it — go to `/oversight/`
directly. To see the **patient**/**clinician** portals, use the register buttons
(they create a profile and route you in).

### Config & stop

- Dev defaults point at `localhost:55432`, db `ehr_test`, user `postgres`,
  store role `portal_ro`. Override via env: `PORTAL_DB_HOST/PORT/NAME/USER`,
  `STORE_DB_USER`, `DJANGO_SECRET_KEY`.
- Stop: Ctrl+C the server, then `docker stop p08pg`.
- **Records are empty** until ingest exists (Phase 3). To show a sample row now,
  ask for the `seed_demo` command.

---

## What works now vs. later

| Now (shell) | Later |
|---|---|
| Register (patient & clinician), login, role routing | Authority *issues* the credential (P2-2) |
| Admin/audit reads the store **read-only** (records, audit, lifecycle) | live federation state |
| Upload / request-access / break-glass buttons → `NotWiredYet` | real ingest (P3-14), consent/grant (P3), break-glass (P3-5) |
| Basic record list views | Drive-style medical department folders & heuristic auto-sorting (Cardiology, Radiology, Pathology, General, Emergency) mapped to attribute policies |

## Future UI Roadmap (Planned)

- **Drive-Style Department Folders & Auto-Sorting:**
  - Patient and Clinician portals will organize records into virtual departmental folders (`📁 Cardiology`, `📁 Radiology & Imaging`, `📁 Pathology & Labs`, `📁 General`, `📁 Emergency / Break-Glass`).
  - Automatic classification/heuristic auto-sorting on record upload (detecting file naming conventions and types, e.g., `*mri*` ➔ Radiology, `*ecg*` ➔ Cardiology) with manual folder override.
  - Direct mapping between department folders and cryptographic access policy attributes (e.g., `dept:cardiology`, `dept:radiology`, `emergency:breakglass`).

Not in the strict `src/` lint/format scope (Django has its own idioms); revisit
if it grows. CI runs the portal tests on SQLite (`portal` job).
