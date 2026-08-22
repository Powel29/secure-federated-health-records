# ADR-0021: Early portal shells + self-service registration (request-then-issue)

- **Status:** Accepted
- **Date:** 2026-08-21
- **Deciders:** Team (developer-experience preference)
- **Task / source:** team decision; extends ADR-0014, ADR-0016, ADR-0019
- **Affects:** new `portal/` Django subsystem (C16), `storage` (C4), CI

## Context

ADR-0014 put the three web portals in Phase 4 and warned that a UI must never
become the access authority. The team prefers to develop **against a real UI**
from the start rather than a terminal, so the portals begin now as growing shells
running in parallel with the backend. The team also wants **self-service
registration** for patients and doctors, which ADR-0014 did not cover.

Registration is security-sensitive: attributes (`role:physician`, …) are only
valid as **authority-signed credentials** that the policy engine verifies
(ARCHITECTURE §8, `credentials.py`). A signup form that *issued* a role would let
anyone satisfy a policy — the exact forgery the system exists to prevent.

## Decision

1. **Start all three portals now as shells** (Django + Bootstrap), reversing
   ADR-0014's Phase-4-only phasing. Graded portal *features* still complete on the
   Phase-4 schedule as their backends land; only the scaffolding moves earlier.
2. **Self-service registration under a request-then-issue rule.** A patient or
   doctor registers themselves (creates a login and a registration *request*); an
   **authority issues** the credential. A signup never yields a working attribute.
3. **The governing invariant:** *a portal account alone grants zero access.*
   Access requires an authority-issued credential; a login with no issued
   credential decrypts nothing.
4. **Storage boundary via Postgres permissions.** Same database, a new `portal`
   schema for Django's own tables, and a **read-only** role for the portal on the
   P0-8 store tables. The portal reads the store live; it can never write it.
   Writes to the store go through the crypto/ingest service, never Django.
5. **Stubs for every unbuilt backend.** `issue_credential(...)` and
   `ingest_upload(...)` raise `NotWiredYet` until `authority` (P2-2) and the
   ingest path (P3-14) exist. The pages work; the actions light up later.

## Consequences

- The team develops with a real UI immediately; the admin/audit portal shows real
  store data (read-only), patient/clinician portals are shells on stubs.
- **This does not gate Phase 0** and must not consume the crypto critical path
  (Powel's chain, and Avaneeth while he is on the Phase-2 identity→authority
  path). Portal work is a parallel track for members with slack.
- A new `portal/` Django subsystem sits beside the FastAPI services; CI gains a
  Django check/test step. `portal/` is outside the strict `src/` ruff/black scope
  for now (Django has its own idioms); revisit if it grows.
- **Downside (honest):** two of three portals are shells on stubs for weeks, so
  some UI may be reworked as the contracts/flows settle. Accepted as the price of
  the team's preferred workflow. The invariant test below is what keeps the
  security story intact while the shells exist.

## The test that protects the invariant

A negative test: **a freshly self-registered doctor — a login with no issued
credential — is denied access.** It proves registration grants nothing on its
own, and it graduates into the P5-1 security suite once decryption exists.

## Alternatives considered

- **Keep portals in Phase 4 (ADR-0014 as-is).** Rejected by team preference.
- **Auto-issue attributes on signup.** Rejected: it destroys the security model
  (anyone becomes a physician). Issuance stays with the authority.
- **Separate database for the portal.** Rejected: it forces a data copy or an
  extra API hop to read the store; same-DB + read-only role gives the wall with
  one live source of truth (ADR-0014 boundary as a Postgres permission).
