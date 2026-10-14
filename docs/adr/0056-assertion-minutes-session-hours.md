# ADR-0056: An emergency assertion lives minutes; the session it opens lasts hours

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Avaneeth → Powel (assertion), Ojas (custodian schemas, deploy) → all four
- **Task / source:** Clinical review 2026-10-12 (issue 10); supersedes the assertion half of ADR-0049
- **Affects:** `breakglass/assertion.py` (`MAX_ASSERTION_TTL`), `api/custodian_schemas.py` (`assertion_ttl_seconds`), `deploy/asgi/facility.py` (default `EMERGENCY_DURATION_SECONDS`), ARCHITECTURE.md §7, README.md

## Context

ADR-0049 capped an emergency assertion at 3 days. An assertion is a one-time
token signed just before the shares are requested, so an unused one that stays
valid for days is a standing permission. Meanwhile the session it opens was
900 s by default, which ends mid-resuscitation: emergency care runs for hours.
The clinical review flagged both as the wrong way round.

## Decision

- An assertion may live at most **15 minutes** (`expires_at - issued_at`),
  matching `create_emergency_assertion`'s own default. The custodian's
  `assertion_ttl_seconds` carries the same bound.
- The session window stays separate configuration. The facility default is
  **4 hours** (an emergency encounter) everywhere, including Compose and
  `run_portal_demo`; a timer demo sets 60–120 s explicitly (ADR-0060). The 3-day cap on the requested window (ADR-0049) and the rule
  that a caller can only shorten the configured window are unchanged.

## Consequences

- A 3-day assertion that ADR-0049 accepted is now refused before its id is
  consumed (`tests/security/test_phase3_assertion_security.py`).
- A deployment that omits `EMERGENCY_DURATION_SECONDS` now gets a 4-hour
  window instead of 15 minutes; the forced rotation fires later. Compose and
  `run_portal_demo` default to the same 4 hours; set
  `EMERGENCY_DURATION_SECONDS` to see expiry live.
- The portal requests a 120 s assertion (`ASSERTION_TTL_SECONDS`) and shows
  that same value on the break-glass page; the custodian refuses more than
  15 minutes.

## Alternatives considered

- **Keep 3 days** (ADR-0049) — an unused assertion is then a standing
  permission.
- **5-minute assertion** — tighter, but clock drift plus a slow audit commit
  could expire it between signing and the facility's check.
