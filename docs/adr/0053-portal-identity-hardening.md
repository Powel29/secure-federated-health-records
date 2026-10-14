# ADR-0053: Portal identity is bound at issuance; the portal's own DB role has no store access

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Avaneeth → Nandini (accounts, clinician portal), Ojas (portal_core, admin portal) → all four
- **Task / source:** Review F17, F36, F41, F42; ADR-0014, ADR-0021, ADR-0033
- **Affects:** `portal/accounts/views.py`, `portal/portal_core/access.py`, `portal/templates/home.html`, `portal/clinician/views.py`, `portal/sql/roles.sql`, `deploy/run_portal_demo.py`, `deploy/seed_portal.py`, `portal/config/settings.py`, `portal/patient/views.py`, `portal/admin_audit/views.py`

## Context

Self-registration bound whatever `patient_id`/`clinician_id` the visitor
typed and logged them in, so the first person to register `doc-301` acted as
that clinician through the custodian. It also wrote a patient-directory row
(name + DOB → subject id) from unverified input. The break-glass page took a
raw `patient_id`, skipping the logged lookup (ADR-0033). Django connected as
the Postgres superuser, so a portal bug could write store tables.

## Decision

- Sign-up records a PENDING request only: no `Profile`, no directory row.
  The `Profile` (login → subject) is created at issuance by an administrator.
  A request for a subject that already has an account is refused.
- `role_required` also refuses any login with a PENDING or DENIED request;
  such users see a "pending approval" page and no custodian call is made.
- Break-glass acts only on the patient the session's logged lookup selected;
  a different or raw `patient_id` is 400.
- Django's `default` connection is a new `portal_app` role that owns the
  `portal` schema and has no privileges on store tables.
- DEBUG defaults off (the loopback demo sets it explicitly); `next` redirects
  stay on-site; uploads other than PDF/PNG/JPEG/text download with `nosniff`;
  a bad registration id is 400; the trace view's link check is three-state.

## Consequences

- Self-registered users cannot use any portal until issuance exists; issuance
  is still the `NotWiredYet` stub (P2-2), so today only seeded accounts work.
- The directory only contains administrator-entered rows.

## Alternatives considered

- **Keep binding at sign-up, gate on ISSUED only** — closes the takeover but
  still lets anyone squat a subject id and plant directory rows.
- **A separate LookupSession model** (review F41) — the Django session is
  already server-side and already holds the logged selection; a new table
  would duplicate it.
