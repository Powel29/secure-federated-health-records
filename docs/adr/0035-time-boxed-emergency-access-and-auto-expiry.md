# ADR-0035: Time-boxed emergency access with forced auto-expiry

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-09-03
- **Deciders:** Powel → all four
- **Task / source:** P3-6
- **Affects:** `lifecycle` (new `expiry.py`, extended `exceptions.py`); the
  threat model; the paper's forward-secrecy claim; Phase 4 API integration
  (P4-2, audit-callback wiring)

## Context

ARCHITECTURE.md §5 step 7 requires that emergency access terminate on its own
-- "no admin action required" -- and that whatever the record becomes after
expiry is protected from what came before. Before this change, a break-glass
session (P3-5, `breakglass.gate.open_emergency_access`) opened a record into
`EMERGENCY_OPEN` with no mechanism that ever moved it back out; the two legal
transitions the state machine already reserves for this
(`EMERGENCY_OPEN -> EXPIRED`, `EXPIRED -> GRANTED`, both in
`LEGAL_TRANSITIONS` since ADR-0030) had no caller. ADR-0003 already commits
the project to simulating the HSM/KMS enforcement of "this key stops working
at time T" with a trusted timer process rather than real hardware.

## Decision

Add `lifecycle.expiry.EmergencyExpiryManager`: a simulated HSM timer, owned
by a dedicated `timer_actor_id` signing identity ("system:hsm-timer" by
default, per ADR-0003 -- never the clinician's key, never the audit
service's key). On expiry it emits two signed `TransitionEvent`s through the
shared `LifecycleStateMachine` (so ADR-0030's consumed-event-id protection
applies to both) -- `EMERGENCY_OPEN -> EXPIRED`, then a forced DEK rotation,
then `EXPIRED -> GRANTED`. The manager tracks an `EmergencySession` per
record carrying both DEK wrappings the session needs: the emergency wrapping
(what the clinician holds) and the baseline wrapping plus its wrapping key
(what the record rotates back to), so rotation needs no further trip through
the policy engine.

Expiry can fire three ways: an explicit `expire_session` call, a
`check_and_expire_due` sweep, or a daemon thread started by
`start_monitor` -- the last of these is what actually delivers "no admin
action required." An `audit_logger` callback parameter is a Phase 4 seam:
end-to-end wiring to `audit.share_custody.release_share_after_commit` and
`audit.chain.append_entry` happens at Phase 4 API integration (P4-2); with
`audit_logger=None`, expiry events are still generated as signed
`TransitionEvent`s and returned to the caller, but do not enter the hash
chain until a Phase 4 caller supplies the real callback.

## Consequences

- **Python "zeroization" is best-effort only.** `expire_session` overwrites
  the session's `emergency_key` reference with 32 zero bytes and drops the
  session, but Python gives no guarantee the original bytes object is
  actually cleared from memory before garbage collection -- immutable
  `bytes`, possible interpreter-level copies. A real HSM would zeroize the
  key material itself. This must appear in the paper's limitations.
- **The timer thread is a trusted process, not a hardware timer.** This is
  the same acceptance ADR-0003 already made: a compromised timer process
  could decline to expire a session or forge non-expiry, and this design
  reduces but does not eliminate that -- the signed, logged rotation makes
  non-expiry detectable in the audit chain rather than silent.
- **A clinician who already decrypted and cached data before rotation keeps
  it.** Forced rotation protects the record's ciphertext going forward --
  the retired emergency key cannot decrypt anything produced after
  rotation -- but nothing at this layer claws back plaintext (or an
  unwrapped pre-rotation DEK) the clinician already holds locally. Stated
  explicitly in `tests/security/test_phase3_expiry_security.py` and must
  appear in the paper as a limitation, not be silently overclaimed as full
  forward secrecy.
- **Without a Phase-4 audit callback wired, expiry events do not enter the
  hash chain.** They are still signed, verifiable `TransitionEvent`s
  returned in `ExpiryResult`, and the manager independently records
  transition metadata in `audit_entries` on every call -- but the standing
  audit chain (P3-3/P3-4) only sees them once P4-2 wires the callback.

## Alternatives considered

- **Admin-triggered expiry** -- rejected. The "no admin action required"
  requirement in ARCHITECTURE.md §5 step 7 is a paper claim under evaluation
  in the course's security module; an admin-triggered design would falsify
  it outright.
- **Tick-only expiry with no background thread** -- rejected as the sole
  mechanism, though still fully supported: `check_and_expire_due` lets any
  caller (a request handler, a cron-style job, a test) sweep due sessions
  without a thread. A background thread (`start_monitor`/`stop_monitor`) is
  added on top because the demo needs to show expiry actually happening
  without anyone polling by hand -- that is the concrete evidence for the
  "no admin action" claim.
