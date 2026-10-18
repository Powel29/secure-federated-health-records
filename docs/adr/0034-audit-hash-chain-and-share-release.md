# ADR-0034: Audit hash-chain encoding, full-entry signing, and savepoint-based log-before-release

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping); `0x1f` field encoding superseded by ADR-0077
- **Date:** 2026-09-03
- **Deciders:** Ojas (P3-3/P3-4 owner) → all four for ratification
- **Task / source:** P3-3, P3-4 (WORKFLOW.md); ARCHITECTURE §2 C10, §5 step 3, §7
- **Affects:** `src/audit/chain.py`, `src/audit/share_custody.py`,
  `src/audit/exceptions.py`, `src/storage/repositories.py` (new
  `get_chain_head`/`list_audit_entries`), `tests/audit/`,
  `tests/security/test_phase3_audit_security.py`

## Context

ARCHITECTURE.md §2 C10 fixes the chain formula:
`h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)`. It names the four
inputs but not their byte encoding, and §5 step 3 adds the log-before-release
precondition ("the audit service computes and commits ... first, and only
then returns its share"). Three decisions with alternatives fell out of
implementing P3-3/P3-4.

## Decision

### 1. Canonical encoding: field-separator join, JSON-canonical `event_data`

`event` in the formula is encoded as
`event_type ‖ 0x1f ‖ json.dumps(event_data, sort_keys=True, separators=(",", ":"))`,
and the four top-level terms (`prev_hash`, `event`, `timestamp`, `actor_id`)
are themselves joined with the same `0x1f` separator used by every other
canonical-payload builder in this codebase (`lifecycle/state_machine.py`,
`consent/service.py`, `breakglass/envelopes.py`). This is encoding, not a
cryptographic construction choice — the formula itself is unambiguous; only
its byte serialization needed fixing, and reusing the project's one existing
convention keeps every signed/hashed payload in the codebase built the same
way.

### 2. The ECDSA signature covers the whole entry, not just `entry_hash`

The chain-hash formula does not include `seq` or `correlation_id`. Signing
only `entry_hash` would leave those two fields unauthenticated — a stored
row could have its `correlation_id` silently swapped without invalidating
anything the chain check inspects. `_entry_signing_payload` therefore covers
`seq, prev_hash, entry_hash, event_type, event_data, actor_id,
correlation_id, timestamp`, and `verify_chain` checks the signature *before*
the hash-chain link/recompute checks (same ordering rationale as ADR-0030
§2: a tampered field is reported as forged, not merely as "chain broken").

### 3. Log-before-release proven via `conn.transaction()` (a psycopg3
savepoint when nested), not a caller-level commit

`release_share_after_commit` wraps its single `append_entry` call in
`with conn.transaction():`. Two other options existed:

- **Call `conn.commit()` directly inside the function.** Rejected: every
  test in this codebase (`tests/storage/conftest.py` and onward) relies on a
  session-scoped connection whose per-test isolation is a `rollback()` after
  each test. A function that commits internally would leak real rows across
  the whole test session, breaking that convention for every module, not
  just `audit`.
- **No transaction guard at all — let `insert_audit_entry` succeed or fail
  and propagate.** Rejected: still correct for "no log, no share" *if*
  nothing downstream is written after the insert, but gives up the
  all-or-nothing guarantee if `append_entry` is later extended (e.g. to also
  update a denormalised head-cache row). The savepoint costs nothing today
  and removes that future foot-gun.

`conn.transaction()` gives atomicity for the append without touching commit
ownership: on success the savepoint releases; on any exception it rolls back
to the savepoint and re-raises, which `release_share_after_commit` catches
and re-raises as `AuditCommitFailedError` *before* its `return` statement —
there is no code path that returns a share without the block having
completed successfully first. Final durability (the outer `COMMIT`) stays
the caller's responsibility, exactly as it already is for every other
`storage.repositories` write in this codebase.

## Consequences

**What this makes work.** `verify_chain`/`verify_full_chain` catch tampering
with any entry field, not just the ones the hash formula names.
`release_share_after_commit` gives P3-5 (`breakglass`, not yet built) a
ready-made custody primitive: hand it a share and event metadata, get the
share back only if the log entry is provably persisted first.

**What this makes hard.** The P3-4 negative test cannot force a *genuine*
Postgres-level write failure without real cross-connection concurrency
(the function always re-derives `seq` from the live chain head, so a
sequential duplicate-`seq` attempt self-heals instead of colliding). The
test instead disables `storage.repositories.insert_audit_entry` at its
exact point of use (`monkeypatch`) and asserts the function raises
`AuditCommitFailedError` rather than swallowing the error and returning a
share anyway. This tests the actual control (the try/except structure
around the commit), not Postgres's own durability guarantee, which is not
this project's to re-prove.

**Honesty caveat.** `get_chain_head`/`append_entry` derive the next `seq`
from a read of the current head with no row lock. Two truly concurrent
callers (two audit-service request handlers, if the service is ever more
than single-threaded) could both read the same head and attempt the same
next `seq`, and only one would durably commit — the other would correctly
raise `AuditCommitFailedError` (fail closed, not a corrupted chain), but the
"loser" caller's break-glass attempt would need to retry. This is a
liveness concern, not a safety one, and is left as a documented limitation
for P4-2 (the audit service process) to address if the demo topology needs
it.

## Alternatives considered

- **Sign only `entry_hash`.** Rejected in decision 2 above — leaves `seq`
  and `correlation_id` outside the tamper-evidence boundary.
- **Persist a genesis entry implicitly on first `append_entry` call** (i.e.
  auto-create genesis if none exists) instead of requiring an explicit
  `create_genesis_entry` + insert first. Rejected: ARCHITECTURE §7 makes
  genesis an explicit bootstrap step ("initialises the hash chain with a
  genesis entry `h_0` and publishes its chain head"); an implicit genesis
  would let any caller silently start a new chain instead of failing
  closed with `EmptyChainError` when the real one is missing (e.g. because
  the DB was never bootstrapped).
- **Real cross-connection race for the P3-4 negative test.** Considered for
  fidelity to "a real Postgres write failure," rejected for this PR: it
  requires either two independent connections that both actually commit
  (which would permanently occupy `seq` values across the shared
  session-scoped test connection used by every other test in the file,
  requiring manual cleanup and reintroducing test-order fragility) or a
  separate schema/connection lifecycle per test, both larger changes to the
  existing test-fixture convention than this task warrants. Flagged for a
  follow-up once P3-5/P4-2 need genuine concurrency behaviour tested.
