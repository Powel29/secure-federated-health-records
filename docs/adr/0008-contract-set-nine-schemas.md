# ADR-0008: Freeze the contract set at nine schemas, not seven

- **Status:** Proposed (part of the all-four contract-freeze PR)
- **Date:** 2026-08-12
- **Deciders:** Powel (proposed) → all four (CONVENTIONS §3 freeze)
- **Task / source:** T02
- **Affects:** `src/contracts/`; CONVENTIONS §3 and the WORKFLOW build order (stale "7")

## Context

Three places name the contract set as **seven** schemas (CONVENTIONS §3, the
WORKFLOW build order, both listing Record, DEKWrapping, TransitionEvent,
AuditEntry, AttributeCredential, Facility, PolicyTree). But the external security
review (ARCHITECTURE §8) added `EmergencyAssertion` and `RequestEnvelope`, and
the T02 task row lists both explicitly. The "7" predates the review.

## Decision

Freeze **nine** schemas: the original seven plus `EmergencyAssertion` and
`RequestEnvelope`. Fix the stale "7" references in CONVENTIONS §3 and the
WORKFLOW build order as part of the freeze PR so the count stops misleading.

## Consequences

- The two security-review structs are first-class frozen contracts, not
  ad-hoc types invented later in `api/` or `breakglass/`.
- `reason_code` ships as a provisional `ReasonCode` enum: the closed-enum
  **shape** is frozen, the clinical taxonomy is not and can change without
  touching a field type.
- Two doc edits are owed alongside the code freeze; tracked here so they are not
  forgotten.

## Alternatives considered

- **Freeze only seven, add the two later** — they would then bypass the
  all-four freeze and the §8 controls would rest on unreviewed types. Rejected.
