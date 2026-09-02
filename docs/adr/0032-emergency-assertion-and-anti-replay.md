# ADR-0032: Emergency assertion validation and anti-replay stores

- **Status:** Proposed
- **Date:** 2026-08-31
- **Deciders:** Tejas → all four for ratification
- **Task / source:** P3-10, P3-11 (WORKFLOW.md); ARCHITECTURE §8
- **Affects:** `src/breakglass/assertion.py`, `src/breakglass/replay.py`,
  `src/breakglass/envelopes.py`, `src/breakglass/exceptions.py`,
  `tests/breakglass/`, `tests/security/test_phase3_assertion_security.py`

## Context

ARCHITECTURE.md §8 defines two security controls that were pending
implementation:

1. **Emergency Assertion** (P3-10): a signed, bound, short-lived structure
   that triggers break-glass.  Before any threshold share is requested, the
   assertion must pass a five-point validation sequence: signature verifies
   → cert chain valid → clinician binding → facility binding → expiry check.

2. **Replay Protection** (P3-11): one-time IDs on emergency assertions,
   share requests, and inter-service request envelopes, rejected on reuse.

The `EmergencyAssertion` and `RequestEnvelope` contracts
(`contracts/messaging.py`) were frozen in Phase 0.  The `TransitionEvent`
contract (`contracts/lifecycle.py`) already declared `event_id` as one-time.
P3-1 (ADR-0030) established the consumed-ID store pattern
(`ConsumedEventIds`) and the ordering invariant (consumption after signature
verification).

## Decision

### 1. Emergency assertion validation follows the §8 sequence exactly

`validate_emergency_assertion` runs six checks in order:

1. ECDSA signature over canonical payload (same `\x1f`-delimited format as
   `lifecycle/state_machine.py` and `consent/service.py`).
2. Certificate chain from clinician cert through facility CA to trusted root
   (via `identity.chain.validate_chain`).
3. `assertion.clinician_id == certificate_common_name`.
4. `assertion.facility_id == expected_facility_id`.
5. `assertion.expires_at > now` (strictly in the future).
6. `assertion.assertion_id` consumed in anti-replay store (if provided).

Failure at any step is fail-closed — no share request is made.

### 2. Consumed-ID stores are thread-safe and per-instance

`ConsumedAssertionIds` and `ConsumedRequestIds` follow the
`ConsumedEventIds` pattern from ADR-0030 §3:

- Per-instance, not module-global — two independent validators do not
  cross-pollinate consumed IDs.
- Thread-safe via `threading.Lock` — concurrent share requests from
  multiple clinicians cannot race past the replay check.
- In-memory for now; persisted store rides with P3-3 (audit chain).

### 3. Consumption happens after signature verification, not before

Same ordering invariant as ADR-0030 §4: a forged assertion cannot burn a
legitimate `assertion_id`.  Proved by
`test_forged_assertion_does_not_burn_legitimate_id` and
`test_forged_envelope_does_not_burn_legitimate_id`.

### 4. Request envelopes validate signature → recipient → replay

`verify_request_envelope` runs three checks in order:

1. ECDSA signature over canonical payload.
2. `envelope.recipient_id == expected_recipient_id` (retargeting defense).
3. `envelope.request_id` consumed (if store provided).

### 5. All implementation lives in `src/breakglass/`

The assertion validator and anti-replay stores live under `breakglass/`
(C11) because they are preconditions of the break-glass threshold gate
(P3-5).  The envelope validator also lives here because its primary
consumer is the share-request protocol between facilities and the audit
service.

## Consequences

**What this makes work.**  P3-5 (break-glass) can now call
`validate_emergency_assertion` as its first step and refuse to proceed if
it fails.  Every inter-service call in the threshold protocol can be wrapped
in a `RequestEnvelope` with replay protection.

**What this makes hard.**  Any change to the validation sequence order or
the consumed-ID store semantics requires updating this ADR and the 56
associated tests.  That is deliberate: the validation sequence is the
safety gate for the project's headline contribution.

**Honesty caveats.**

- The in-memory consumed-ID stores do not survive a process restart.
  P3-3 lands a persisted store that closes this gap.
- Thread safety is via `threading.Lock`, which is correct for a
  single-process multi-threaded server but does not extend to
  multi-process deployments.  The persisted store (P3-3) closes this gap
  too.

## Alternatives considered

- **Put assertion validation in `lifecycle/`.**  Rejected: the state machine
  validates transition events, not emergency triggers.  Mixing the two
  would blur the module boundary and make `lifecycle` depend on `identity`
  (certificate chain validation), which ARCHITECTURE §4 does not list.
- **A single `ConsumedIds` class for all ID types.**  Rejected: assertion
  IDs and request IDs have different error types and the caller needs to
  know which kind of replay was detected (for audit logging).
- **Skip certificate chain validation in the assertion validator (leave it
  to the API layer).**  Rejected: ARCHITECTURE §8 lists "signature verifies
  against a currently-valid clinician certificate" as step 1, and
  "currently-valid" means the cert itself must be checked, not just the
  signature.  Splitting this would let a caller forget the chain check.

