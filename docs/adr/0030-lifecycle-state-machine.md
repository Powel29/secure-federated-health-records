# ADR-0030: Key-lifecycle state machine — transition set and consumed-id defense

- **Status:** Proposed
- **Date:** 2026-08-31
- **Deciders:** Powel (P3-1 owner) → all four for ratification
- **Task / source:** P3-1 (WORKFLOW.md); ARCHITECTURE §2 C9, §5 flows
- **Affects:** `src/lifecycle/state_machine.py`, `src/lifecycle/exceptions.py`,
  `src/contracts/lifecycle.py` (TransitionEvent; already frozen),
  `tests/lifecycle/`, `tests/security/test_phase3_security.py`

## Context

`ARCHITECTURE.md §2 C9` calls the lifecycle state machine "the spine of the
project" and enumerates four states — `GRANTED`, `REVOKED`, `EMERGENCY_OPEN`,
`EXPIRED`. `§5` walks three data flows that imply a specific set of legal
transitions but never lists them exhaustively. `TransitionEvent`
(`contracts/lifecycle.py`) is frozen: it fixes the wire shape (event_id,
record_id, from_state, to_state, actor_id, reason_code, issued_at, nonce,
signature) and declares two properties this module has to honour — the
signature covers a canonical serialization of the fields, and `event_id` is
"one-time; consumed-id store rejects reuse."

Two decisions with alternatives fell out of implementing P3-1: what the legal
transition set actually is, and where the consumed-id store lives.

## Decision

### 1. The legal transition set is six pairs, not more

```
LEGAL_TRANSITIONS = {
    (GRANTED,        REVOKED),          # consent withdrawal / revocation
    (GRANTED,        EMERGENCY_OPEN),   # break-glass on a granted record
    (REVOKED,        GRANTED),          # re-consent / consent renewal
    (REVOKED,        EMERGENCY_OPEN),   # emergency for a revoked patient
    (EMERGENCY_OPEN, EXPIRED),          # time-box expiry
    (EXPIRED,        GRANTED),          # automatic post-rotation baseline
}
```

This is exactly what `ARCHITECTURE §5` walks. Anything else — self-transitions,
`GRANTED → EXPIRED` bypassing the emergency window, `EMERGENCY_OPEN → REVOKED`
for premature termination, `EXPIRED → EMERGENCY_OPEN` for a second emergency
without first rotating — is refused by `validate_transition` with
`IllegalTransitionError`.

Two consequences of this exact set:

- **Emergency-open is only reachable via GRANTED or REVOKED.** A second
  emergency after a completed cycle goes `EXPIRED → GRANTED → EMERGENCY_OPEN`;
  the automatic post-rotation step is not skippable.
- **The state machine cannot express "premature emergency termination".** If
  the team decides that flow is real, it needs its own ADR extending
  `LEGAL_TRANSITIONS` and a matching test — silent addition would put the
  spine out of sync with `ARCHITECTURE §5`.

### 2. Signature verification runs before legality checks

`verify_transition_event` calls `crypto_core.verify` before
`validate_transition`. A tampered `to_state` is therefore reported as
`InvalidSignatureError` (the event was tampered), not as
`IllegalTransitionError` (the event stated something illegal). The alternative
ordering hides tampering behind a policy error and makes the wrong claim about
what went wrong.

`create_transition_event` keeps legality first — there is no signature yet.

### 3. Consumed-id store is a module-owned object, not a module global

`ConsumedEventIds` is a class with `.consume(event_id)`/`.has_seen(event_id)`,
constructed per `LifecycleStateMachine` unless the caller passes one in. This
means:

- Two independent state machines do not share replay history (proven by
  `test_two_machines_do_not_share_consumed_ids`), so one bad actor cannot
  poison another flow by burning IDs;
- A caller who *wants* shared replay defense across two composed machines
  passes the same `ConsumedEventIds` into both (proven by
  `test_shared_consumed_store_is_honored_when_passed_in`);
- The in-memory implementation is intentional for P3-1 — a persisted store
  rides with the audit chain in P3-3 and swaps in via the same interface.

### 4. Consumption happens after signature verification, not before

`apply_transition` order: verify signature → check `from_state` matches →
consume `event_id`. Consuming before verification would let a forged event
burn a legitimate id: attacker observes an id in flight, forges an event with
that id, presents it first, and the real event then fails as a spurious
replay. `test_sec_consumed_id_check_runs_after_signature_check` locks this
ordering in.

## Consequences

**What this makes work.** Every ARCHITECTURE §5 flow — consent, revocation,
break-glass, time-box expiry, automatic re-baselining — is a legal transition
that produces a signed, verifiable, non-replayable event. The signed event
becomes the audit chain's payload in P3-3 without translation.

**What this makes hard.** Any workflow that needs a not-listed transition
(e.g. premature emergency close, forced expiry-without-emergency, admin
override) requires an ADR and a new legal-transition entry. That is deliberate:
the state machine is the spine, and quiet extensions to it are precisely the
class of change most likely to make the paper's headline claim false.

**Honesty caveats.**

- The in-memory `ConsumedEventIds` does not survive a process restart, so a
  crashed-then-restarted state-machine process would accept an event it had
  already applied. P3-3 lands a persisted store that closes this gap.
- The state machine does not persist a record's current state — the caller
  passes it. If the caller reads a stale current state (e.g. after another
  process's transition), a stale event may pass state-matching and apply
  again. This is a caller-concurrency concern, not a state-machine concern,
  and is closed at the storage layer (`storage.upsert_lifecycle_state` +
  Postgres row locks).

## Alternatives considered

- **Include `EMERGENCY_OPEN → REVOKED` and `EXPIRED → REVOKED`/
  `EMERGENCY_OPEN`.** Rejected: none of these appear in ARCHITECTURE §5, and
  adopting them silently in P3-1 would either make the state machine broader
  than the documented model (the doc becomes wrong) or ship dead states that
  never fire (the code becomes wrong). If real, they each need their own ADR
  saying *when* they fire and *who* signs — those constraints are load-bearing.
- **Persisted consumed-id store in P3-1.** Rejected: pulls storage into the
  spine before the audit chain lands. P3-3 owns the audit chain and the
  persisted replay defense together.
- **Static module-global `_SEEN_IDS = set()`.** Rejected outright: two tests
  running in the same process would poison each other, and two independent
  facility-node instances would silently share replay state through a global
  they never opted into. The subtle-shared-state bugs this produces are
  the kind you find in production, not in tests.
- **Verify legality before signature in `verify_transition_event`.** Rejected:
  reports tampering as an "illegal transition" error, which is a factually
  wrong claim about what an attacker did. Fixing this discovered by the field-
  tampering parametrised negative test caught the wrong-error-code failure
  during P3-1 implementation.
