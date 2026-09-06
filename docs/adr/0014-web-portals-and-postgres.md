# ADR-0014: Three web portals replace the dashboard; PostgreSQL as storage

Status: Accepted (2026-08-18) — **reverses part of ADR-0013 and PROJECT §4B**

## Context
Earlier decisions scoped the UI down to a single read-only terminal dashboard
(ADR-0013) and explicitly rejected a multi-portal web UI as scope-inversion
(PROJECT §4B). The team has now chosen to reverse that.

## Decision
1. Replace the terminal dashboard entirely with **three role-based web portals**
   (patient, clinician, admin/audit), built in Django + Bootstrap.
2. Use **PostgreSQL** as the record store, replacing SQLite.
3. Adopt from the alternative proposal: a proper **patient consent model**
   (signed, scoped, expiring, request-then-approve), **patient notifications**,
   **correlation IDs** on audit events, and **PEP/PDP** vocabulary for the
   existing policy layer.

## Reason recorded
Team preference for a role-based web UI over the terminal dashboard.

## Consequences — and the guardrail that keeps novelty intact
- The dashboard tasks (old P0-9, P1-7) are removed; new portal tasks P4-10/11/12
  and a notification task P4-13 are added. *(These were later renumbered to
  P4-7/8/9 and P4-10 at Phase-3 close to eliminate the P4-7..P4-9 gap; see the
  current WORKFLOW.md. This paragraph keeps the original numbers as the
  historical record of what this ADR authorised.)*
- **Critical boundary:** the portals and Postgres **store data and identify
  users; they never decide access.** Decryption is still gated by the Shamir
  threshold and the policy/key wrappings. Django login answers "who is asking",
  not "may this be decrypted." If portal-login or a database check ever becomes
  the thing that releases a key, the project's central novelty
  (no-single-party access, logging-as-precondition) is destroyed. This boundary
  is a standing review item.
- Postgres holds only ciphertext, wrapped keys, and the coded index — a full DB
  compromise still yields gibberish.
- Cost: a second web framework (Django) now sits alongside the FastAPI services;
  the crypto core is unchanged but is a smaller share of the total build.
- Consent, notifications, correlation IDs, and PEP/PDP are genuine improvements
  adopted from the alternative proposal; the threshold gate, state machine,
  logging-as-precondition, proxy re-encryption, searchable encryption, and the
  traffic-analysis module are all retained unchanged.

## What was NOT adopted from the alternative proposal
- PostgreSQL/Django as the **access authority** — rejected; keys decide access.
- Replacing the Shamir break-glass gate with a policy-only emergency service —
  rejected; that is the project's headline contribution.
- mTLS everywhere — still rejected (breaks the traffic-analysis capture module).
- Monitoring/anomaly detection — still cut (PROJECT §6).
