# ADR-0044: Break-glass enforces the assertion's patient binding; the store reconciles an expired time-box

- **Status:** Proposed; the state-reconciliation half is superseded by ADR-0050 (review N1)
- **Date:** 2026-10-02
- **Deciders:** Powel (proposal) — pending ratification by the `src/api` owner (Avaneeth) and `src/lifecycle` owner
- **Task / source:** automated end-to-end run of the portal flows (`tests/e2e/portal_flows.py`); ARCHITECTURE.md §8; ADR-0043 (re-baseline persistence gap, P5-4)
- **Affects:** `src/api/hospital.py` (break-glass endpoint), `tests/api/test_breakglass.py`, ARCHITECTURE.md §8

## Context

Two defects surfaced from the live demo stack:

1. `EmergencyAssertion.patient_id` is documented as bound ("this assertion opens
   this patient only"), but the facility's break-glass endpoint validated the
   five assertion checks and never compared the assertion's patient with the
   record's patient. An assertion for `pat-103` opened `rec-001`
   (`pat-101`'s record) and left it `emergency-open`.
2. The expiry timer signs `emergency_open → expired → granted` into the chain
   but does not write the store. `lifecycle_state` stayed `emergency_open`
   after the time-box, so every later break-glass on that record was refused as
   an illegal `emergency_open → emergency_open` transition (the gap ADR-0043
   records for P5-4).

## Decision

1. Add a sixth check in the break-glass endpoint, after the record is loaded
   and before any share is combined or any state changes: `record.patient_id`
   must equal `assertion.patient_id`, else HTTP 403, with a
   `breakglass_patient_binding` denial written to the audit chain.
2. Before choosing the transition's source state, reconcile it: if the store
   says `emergency_open` but the expiry manager holds **no** session for the
   record (`SessionNotFoundError`), record `granted`. A registered session,
   including one past its deadline but not yet swept, is left alone and the
   request still fails closed.

## Consequences

- A mismatched assertion has no side effect on the record. The custodian still
  commits the audit entry and releases share 3 before the facility is called
  (log-before-release, ARCHITECTURE.md §7), so the attempt is in the chain as a
  share release plus a patient-binding denial.
- Re-break-glass after expiry works. This is a stop-gap: the store is told
  `granted`, but the rotated record and wrapping from expiry are still not
  persisted, so the forward-secrecy rotation remains in memory only. Full
  re-baseline persistence stays open under P5-4.
- After a facility restart the in-memory session is gone, so a record left
  `emergency_open` becomes `granted` on the next break-glass attempt rather
  than staying locked. The emergency wrapping is still in the store in both
  cases; the restart case therefore reopens access without the timer having
  rotated anything.
- A narrow race remains: between persisting `emergency_open` and registering
  the session, a concurrent attempt would see no session and reconcile. It
  would then fail on the replay store or the shares, not succeed silently.

## Alternatives considered

- **Check the patient binding in the custodian only.** The custodian has no
  record metadata and the facility is the policy enforcement point; the
  facility must check regardless.
- **Persist the rotated record and wrapping at expiry.** The correct fix, but
  the custodian supplies a throwaway baseline wrapping key (ADR-0043), so
  persisting would make the record permanently undecryptable. Needs a design
  for recompiling the policy root secret; left to P5-4.
- **Let the state machine allow `emergency_open → emergency_open`.** Would
  allow overlapping time-boxes and weaken the lifecycle state machine; rejected.
