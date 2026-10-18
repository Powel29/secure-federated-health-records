# ADR-0068: The break-glass transition is signed by the clinician inside the custodian

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (decision, review D8-a; owns `breakglass`, `lifecycle`); Ojas (custodian), Avaneeth (`api`) to review
- **Task / source:** review D8 / F11 (claim C7)
- **Affects:** `breakglass.gate.open_emergency_access` (takes `transition_event` + `actor_public_key`, no signing key); `custodian.sign_emergency_transition`, `custodian.prepare_unlock`; `api/custodian_service.py`; `api/hospital.py` (verification, new `GET /records/{id}/lifecycle`); `api/schemas.py` (`transition_event` replaces `lifecycle_signing_key_pem`); demo, scenario, bench

## Context

The `GRANTED/REVOKED -> EMERGENCY_OPEN` event was signed with a throwaway key
the custodian minted per unlock and sent to the facility -- a private key on the
wire -- and nothing could verify the event afterwards. C7 ("transitions are
non-repudiable") did not hold for the transition that matters most.

## Decision

1. Before an open, the custodian reads the record's state from the facility
   (`GET /records/{id}/lifecycle`, signed, custodian/bootstrap only) and signs
   `state -> EMERGENCY_OPEN` with the **clinician's own key**, inside the
   custodian (`custodian.sign_emergency_transition`, the existing
   `lifecycle.create_transition_event`). The key never leaves the custodian
   (ADR-0043). A join signs nothing; an `expired` record (mid-rotation) is a
   409.
2. The facility, before any side effect, requires the event to be this
   record's, from its current state (else 409, sign again), into
   `EMERGENCY_OPEN`, by the asserting clinician, with the assertion's reason,
   issued within the assertion lifetime, and its signature to verify against
   the clinician certificate it has already validated. After claiming the
   state it applies the event through the state machine, which consumes the
   event id (a replay is a 400).
3. The gate itself verifies the event against the clinician's key and its
   record and source state before it combines a single share.
4. `lifecycle_signing_key_pem` is gone from the API; sending it is a 422.

## Consequences

- C7 holds at the system level: the event verifies under the clinician's key
  and no other (`test_c7_...`), a foreign-signed event opens nothing, and
  mutation C7a (signature check skipped) turns the negative red.
- One more round trip per open (the state read). A state change between the
  read and the open costs a retry, never a wrong transition.
- **Residual:** the expiry timer's own events are still signed by a fresh
  per-process timer key (ADR-0003), so they are not verifiable after the
  process ends. The custodian signs as the clinician (ADR-0043 simplification).

## Alternatives considered

- **D8-b: a facility service key signs as witness** -- verifiable, but proves
  "the facility says so", not which clinician opened the record.
- **The clinician's key travels to the facility** -- breaks ADR-0043.
