# ADR-0046: P5-1 claim registry, system-level evidence, strict-xfail policy and mutation check

- **Status:** Proposed
- **Date:** 2026-10-07
- **Deciders:** Powel (implementer; P5-1 is Ojas's per WORKFLOW.md) → Ojas to review (Powel built several of the controls under test), then all four
- **Task / source:** P5-1 (WORKFLOW.md); CONVENTIONS.md §5; ADR-0016; review `docs/review/2026-10-07-fix-proposals.md` (F34, F42 and the findings cited per claim)
- **Affects:** `tests/security/` (new `claims.py`, `_claim_collector.py`, `mutations.py`, `test_claim_registry.py`, `test_p51_system_claims.py`; `conftest.py`), `pyproject.toml` (marker), claim tags on existing tests in `tests/security/` and `tests/api/`

## Context

P5-1's "Done when" is that all eleven negative tests pass, each mapped to a
paper claim. All eleven already had tests, but almost all exercised a single
module. The 2026-10-07 review shows that for about half the claims, the module
holds while the running system does not (share 3 released to anyone, nothing
rotated on expiry, unverifiable break-glass events, in-memory replay stores,
an uncredentialed key endpoint, no BOLA test). Three choices follow:

1. how a test is tied to a claim;
2. what counts as evidence for the paper;
3. what to do with a correct test that fails today.

## Decision

1. **A `claim(id, level)` pytest marker** ties each test to C1–C11
   (`tests/security/claims.py`). `level` is `module` or `system`.
   `python -m tests.security.claims --table` regenerates the
   claim → test → status table that P6-4's security-properties table is built
   from.
2. **Only system-level tests decide a claim.** A claim "holds" only if every
   one of its system tests runs without `xfail`. `test_claim_registry.py` fails
   if any claim lacks a system test, if a tag names an unknown claim or level,
   or if an `xfail` is not strict or cites no review finding.
3. **Strict xfail for known-false claims.** A system test that fails today
   keeps its full-strength assertion and is marked
   `xfail(strict=True, reason="<finding>: …")`. CI stays green, the failure is
   on record in the test itself, and the run turns red the day the fix lands,
   so the marker must be removed. The paper may not state a claim while any of
   its system tests is `xfail`.
4. **Mutation check as standing evidence.** `python -m tests.security.mutations`
   disables each control by monkeypatching at pytest start-up and re-runs the
   claim's holding tests. Each must go red under at least one mutation. The
   result is recorded in `docs/review/p5-1-evidence.md`.
5. **CI fails rather than skips without Postgres** in `tests/security/`
   (review F42), so the C2 and C5 evidence cannot silently drop out.

## Consequences

- P5-1's literal "Done when" is reachable only as the review fixes land. Until
  then the state is honest and visible: 11 claims written, 4 hold, 7 fail
  against named findings. As markers come off, P5-1 measures the review's
  progress.
- CI stays green with known failures. Strict mode means the green cannot go
  stale: a silently fixed control breaks the build until someone updates the
  claim's status.
- **Honest downsides.**
  - `xfail` can be misread as "the test is wrong". The reason string and the
    registry meta-test make the finding explicit, but reviewers still need to
    read it.
  - The registry runs a nested `pytest --collect-only` subprocess, which adds
    a few seconds to the suite.
  - The mutations are monkeypatches written against current function names. A
    refactor can make one stop applying, so re-run the check after touching a
    control.
  - The system tests share `tests/api/conftest.py`'s PKI fixtures, which
    couples the two suites.
- C2 and C5 rows need a Postgres run to complete the mutation log (CI has one;
  the author's machine did not).

## Alternatives considered

- **A naming convention or docstring parsing instead of a marker.** Rejected.
  It is not machine-checkable without fragile parsing. A marker is first-class
  in pytest and filterable (`-m claim`).
- **Skip, rather than xfail, for failing claims.** Rejected. A skipped test
  asserts nothing and never alerts when the fix lands.
- **Leave failing system tests failing (red CI) until fixed.** Rejected. It
  blocks every unrelated PR for weeks and trains people to ignore red CI.
- **Weaken the assertions to what the system does today.** Rejected outright.
  It turns evidence into documentation of the bug (negative-security-test
  skill: never weaken a test to make it pass).
- **A mutation-testing tool (mutmut and similar).** Deferred. Generic operator
  mutations are slow, noisy and do not target the control a claim names.
  Hand-written mutations aimed at each control say exactly what was disabled.
