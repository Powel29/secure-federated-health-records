# ADR-0074: Open emergency sessions survive a restart as keyless rows and are closed at startup

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (proposal; owns `lifecycle`); Avaneeth (`api`, `storage`) to review
- **Task / source:** review F5 (D7 decided by ADR-0058); ADR-0069 residual "crash mid-rotation"; handoff 2026-10-15 item 6
- **Affects:** migration `0006_emergency_sessions.sql`; `storage.repositories` (`save/delete/list_emergency_session(s)`); `api/repository.py`; `lifecycle/expiry.py` (`SessionStore`, `attach_session_store`, `recover_session`, `has_session`); `api/rotation.py` (`RepositorySessionStore`, `recover_emergency_sessions`, recovered-session path in `FacilityRotator`); `lifecycle/rotation.py` (`plan_rotation_via_policy`); `api/hospital.py` (wiring at startup); share holders accept a later generation; `PROJECT.md` §5 caveat 6

## Context

The emergency key exists only in the facility process. Two failures left a
record stuck:

- a facility restart during the window left it `emergency_open` with no
  session anywhere, so it could neither be joined nor expire (F5);
- a crash after the rotation's store commit but before both share deposits
  left no holder set matching the stored emergency wrapping, so the record
  could never be broken into again (ADR-0069's residual).

## Decision

1. When a session opens, the expiry manager writes a row to
   `emergency_sessions`: record id, facility, the state to return to, opener,
   correlation id and times -- **no key material**. If the row cannot be
   written the session is not opened (fail closed). The row is deleted once
   the expiry has finished.
2. At startup, a facility reads **only its own rows**. For each record still
   `emergency_open` or `expired` it registers a recovered session: no key, due
   at once, so it cannot be joined. A row whose record is already back at
   baseline is dropped.
3. The next sweep expires it as usual. Finding no key, the rotator recovers
   the DEK through the record's own policy with the authoring keys of its
   leaves (`plan_rotation_via_policy`, the same path revocation uses,
   ADR-0073), plans a full rotation from the store as it stands, stores it
   and hands out new shares. If the store already shows `expired`, the
   `EMERGENCY_OPEN -> EXPIRED` entry was appended before the crash and is not
   appended again.
4. Share holders accept **any later generation** instead of exactly the next
   one: after a crash between deposits one holder can be a generation ahead,
   and the recovered rotation starts after the store's.

## Consequences

- A restart closes every session the facility held, from the restart on;
  clinicians re-declare if they still need the record.
- Old shares and old search tokens are dead after recovery, as after a normal
  expiry (claim C4; `tests/security/test_restart_recovery.py`, which the C4
  mutation turns red).
- Recovering the DEK through the policy gives the facility no new power: it
  already fetches every leaf's authoring key at each rotation, and those are
  the holder keys (ADR-0026).
- The timer key is fresh per process, so the recovered transitions are signed
  by the new process's timer identity.
- Generations may now skip; they still never repeat or go back.

## Alternatives considered

- **Persist the rotation plan.** It holds the new DEK and shares; storing them
  needs a key to seal them under, which is the problem being solved.
- **Persist the emergency key sealed under a facility key.** Puts a standing
  decryption capability in the store for the whole window.
- **Leave stuck records for an operator to re-provision.** The status quo;
  fails closed but needs manual work after every crash.
