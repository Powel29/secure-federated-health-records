# ADR-0050: Every lifecycle state change is a compare-and-set; the expiry timer mirrors and retries

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Avaneeth (api, storage) → Powel (lifecycle) → all four
- **Task / source:** Review N1, N2, F7, F12, F20; supersedes the reconciliation half of ADR-0044 and the store-mirror design in ADR-0047
- **Affects:** `api/hospital.py` (break-glass, revoke, ingest), `api/repository.py` (`insert_lifecycle_state`, in-memory `last_event_id`, `RecordExistsError`), `storage/repositories.py` (`insert_lifecycle_state`), `lifecycle/expiry.py` (`state_writer`, retry/backoff, `unregister_session`), `lifecycle/exceptions.py` (`StateConflictError` moved here), `api/audit_client.py` (mirror removed), `deploy/asgi/facility.py`

## Context

`transition_lifecycle_state` existed but nothing called it. Every write was an
unconditional upsert: two concurrent break-glasses both succeeded; the
ADR-0044 reset wrote `granted` whenever *this* process held no session, racing
another facility's live session; and the ADR-0047 timer mirror wrote `granted`
over whatever was stored, making the D7 un-revoke persistent. A failed expiry
deleted the session first and killed the monitor thread.

## Decision

- Break-glass claims the state with a compare-and-set before running the gate
  (`expected = stored state`, `new = EMERGENCY_OPEN`); a lost race is 409.
  Any failure after the claim (gate refusal, audit outage, session error)
  undoes it and unregisters the session. The signed event is recorded and
  `last_event_id` set against the claimed state.
- Revoke is a compare-and-set from its event's `from_state`; a record in any
  other state (e.g. `EMERGENCY_OPEN`) is refused with 409 before anything is
  written. A failed write undoes the claim.
- Ingest creates the state row insert-only. `upsert_lifecycle_state` remains
  for test seeding only.
- The ADR-0044 reset is removed. A stored `emergency_open` with no session at
  this facility is a 409, not a silent reset; F5 (decision D7) owns proper
  restart reconciliation.
- The expiry manager owns the store mirror: after each audit append it calls
  `state_writer(record_id, from_state, to_state, event_id)` — the repository's
  compare-and-set. `create_hospital_app` attaches it. A conflict is logged and
  never overwritten. Any other failure leaves the session claimed as
  `expiring`, retries with backoff (1 s doubling to 60 s), and resumes where it
  stopped without re-signing an emitted transition. The monitor survives every
  failure; access stays closed meanwhile.

## Consequences

- C6 now holds at the API (`test_c6_…` lost its xfail): the compare-and-set,
  not `LEGAL_TRANSITIONS`, is what refuses there, so the mutation check gained
  C6b.
- Revoke on Postgres returns 501 instead of a 500 after partial writes: the
  store still has no in-place record rotation (F10, blocked on D3/D4).
- A facility that restarts mid-session leaves its record `emergency_open`
  until F5 lands; break-glass on it is refused (fail closed) rather than
  reset.
- Expiry still ends at `GRANTED` (D7 open), but it no longer overwrites a
  state someone else changed.

## Alternatives considered

- **Keep the mirror in `audit_client`** — two writers, and its failures could
  not participate in the retry.
- **One DB transaction for state + event** — the facility connection is
  autocommit; the claim/undo sequence gives the same no-trace property
  without restructuring the repository.
