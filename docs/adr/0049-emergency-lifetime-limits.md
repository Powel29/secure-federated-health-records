# ADR-0049: Three-day ceiling on emergency assertions and windows; the facility's time-box is a maximum

- **Status:** Proposed — assertion ceiling superseded by ADR-0056
- **Date:** 2026-10-11
- **Deciders:** Avaneeth (chose 3 days) → Powel (assertion), Ojas (custodian schemas) → all four
- **Task / source:** Review F6; ARCHITECTURE.md §7 ("Configuration": the time-box is configuration), §8 ("nothing issues forever")
- **Affects:** `breakglass/assertion.py` (`MAX_ASSERTION_TTL`, `ASSERTION_CLOCK_SKEW`, `AssertionLifetimeError`), `api/schemas.py`, `api/custodian_schemas.py`, `api/hospital.py`, `lifecycle/expiry.py` (`default_duration_seconds`), `BreakglassUnlockResponse.expires_at`

## Context

`emergency_duration_seconds` had no bound and overrode the facility's
configured duration; a huge value raised `OverflowError` after state was
written. An assertion's `expires_at` had no maximum and `issued_at` was never
checked, so a ten-year assertion was a standing permission.

## Decision

- An emergency assertion may live at most **3 days** (`expires_at -
  issued_at`), and `issued_at` may be at most 30 seconds in the future.
  Violations raise `AssertionLifetimeError` before the one-time id is consumed.
- A caller may request a window of at most 3 days (schema bound), and the
  facility uses `min(requested, configured)`: the caller can only shorten the
  configured time-box. The response returns the real `expires_at`, which the
  custodian reports instead of computing its own.
- The custodian's `assertion_ttl_seconds` and `emergency_duration_seconds`
  carry the same 3-day bound.

## Consequences

- The 3-day ceiling is generous for an emergency; it is a hard cap, not a
  target. The configured duration (900 s by default) is what a session gets.
- The custodian's previous assertion TTL cap was 1 hour; it is now 3 days, so
  a longer-lived assertion is possible than before (still single-use).

## Alternatives considered

- **300 s assertion ceiling** (the review's proposal) — the team chose 3 days.
- **Let the caller extend the window** — contradicts §7: the time-box is
  configuration.
