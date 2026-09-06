# ADR-0009: TransitionEvent carries no expiry_ts in the v1 freeze

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-08-12
- **Deciders:** Powel (proposed) → all four (CONVENTIONS §3 freeze)
- **Task / source:** T02
- **Affects:** `src/contracts/lifecycle.py` (`TransitionEvent`)

## Context

CONVENTIONS §4 uses `contract: add expiry_ts to TransitionEvent` as its worked
**example of a future contract-change PR**. That framing means `expiry_ts` is
illustrated as a change not yet made — so including it in the initial freeze
would contradict the document that defines the freeze process.

## Decision

`TransitionEvent` v1 has no `expiry_ts` field. Emergency-open time-boxing is
carried today by the emergency-key lifetime and `EmergencyAssertion.expires_at`.
If the team wants the expiry on the transition event itself, that is the first
post-freeze `contract:` PR — and it will supersede this ADR.

## Consequences

- The initial freeze matches the example in CONVENTIONS §4 exactly; no reader is
  left wondering whether the field is already there.
- If lifecycle work later needs per-event expiry, it is a one-field contract
  change with a ready-made example title — cheap, and now on the record.

## Alternatives considered

- **Include `expiry_ts` now** — pre-empts a decision the docs frame as a future
  change, and adds a field with no current consumer. Rejected, revisit if
  lifecycle (T20/T25) needs it.
