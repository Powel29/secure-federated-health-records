# ADR-0058: Expiry returns a record to its pre-emergency state (EXPIRED -> REVOKED)

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Avaneeth → Powel (`lifecycle`) → all four
- **Task / source:** Clinical review 2026-10-12 (issue 3); extends ADR-0030, ADR-0035
- **Affects:** `lifecycle/state_machine.py` (`LEGAL_TRANSITIONS`), `lifecycle/expiry.py` (`EmergencySession.return_state`, `register_session`), `api/hospital.py`, WORKFLOW.md P3-1 note

## Context

`REVOKED -> EMERGENCY_OPEN` is legal (an emergency can override a withdrawal),
but expiry always ran `EMERGENCY_OPEN -> EXPIRED -> GRANTED`. A patient's
revocation therefore silently became a grant once any emergency on that record
ended. The state machine comment requires an ADR to add a transition.

## Decision

Add `EXPIRED -> REVOKED` (seven legal transitions). The expiry manager records
the state the record was in when break-glass opened (`return_state`, GRANTED
or REVOKED, required by `register_session`) and its second signed transition
goes back there. The facility passes the state it claimed from.

## Consequences

- An emergency can no longer undo a revocation; tested in
  `tests/security/test_phase3_expiry_security.py`.
- `register_session` callers must now say where the record returns to; any
  other value is refused.
- The forced DEK rotation at expiry is unchanged: the baseline wrapping it
  re-creates is the one the record had before the emergency.

## Alternatives considered

- **Always return to GRANTED and re-run revocation afterwards** — two extra
  transitions and a window in which the record is wrongly GRANTED.
- **Forbid `REVOKED -> EMERGENCY_OPEN`** — blocks an emergency for a patient
  who revoked a clinician's routine access.
