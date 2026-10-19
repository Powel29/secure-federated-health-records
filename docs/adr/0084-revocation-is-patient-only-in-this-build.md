# ADR-0084: Revocation is patient-only in this build

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** Ojas (proposal) → all four (changes `ARCHITECTURE.md` §5 and `PROJECT.md` §5 wording)
- **Task / source:** review F10 remainder ("Home-authority revocation not wired"); ADR-0080
- **Affects:** `ARCHITECTURE.md` §5 "Revocation", `PROJECT.md` §5 item 1; no code

## Context

`ARCHITECTURE.md` §5 said "Patient or home authority signs a revocation
request". ADR-0080 implemented the patient-signed path only: the facility's
`/records/{id}/revoke` verifies a `GRANTED -> REVOKED` transition against the
patient certificate. `records.revocation.check_revocation_authorization`
accepts a home authority at module level, but no facility endpoint takes an
authority-signed revocation, and the facility holds no authority
verification keys. The paper must not claim a path the system cannot run.

## Decision

Narrow the documents to what is built: only the patient revokes in this
build. `ARCHITECTURE.md` §5 step 1 and `PROJECT.md` §5 item 1 say so and
name home-authority revocation as future work.

## Consequences

- The claim matches the code and its tests; nothing to build before the
  paper.
- A patient who cannot sign (lost device, incapacity) has no revocation path
  in the demo. That is a real gap for a health system and belongs in the
  limitations paragraph.

## Alternatives considered

- **Wire home-authority revocation** — load each authority's verification
  key into facility configuration (like `AUTHORITY_URLS`), accept a
  revocation signed under it for records whose stored owner leaf names that
  authority, with a one-time id and a denial entry on refusal. About a day
  across `api/`, `deploy/` and tests, plus a negative test. Not chosen now
  because nothing in the scenario or evaluation exercises it; reopen if the
  team wants the delegate story in the demo.
