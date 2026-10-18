# ADR-0065: One-time declare token; the case page refreshes by GET and only joins

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (proposal); Nandini (clinician portal) to review
- **Task / source:** re-declare loop found on `main` after PR #40
- **Affects:** `portal/clinician/views.py` (`breakglass`, `_show_record`), `portal/templates/base.html`, `portal/templates/clinician/{breakglass,case}.html`, `portal/portal_core/services.py` (`custodian_breakglass(join_only=)`), `portal/portal_core/testing.py`; ADR-0057, ADR-0062

## Context

A single-record declaration renders the case page as the response to the
declare POST. At expiry the page's countdown script called
`window.location.reload()`, and reloading a POST response re-sends it. PR #40
keeps the identified patient in the session until the care episode closes, so
the re-sent declaration was accepted: every window opened a new break-glass,
released share 3 again and notified the patient again (observed live, cases
opened exactly one window apart).

A second route to the same effect: viewing a case (a GET) joined the open
session through `custodian_breakglass` without `join_only`, so a view landing
just after the facility's timer had re-baselined the record would *open* a new
emergency instead of failing.

## Decision

1. **One-time declare token.** Every render of the break-glass form mints a
   random token (`secrets.token_urlsafe(32)`) into the session and the form.
   A declaration pops the session token and compares it in constant time with
   the one sent, before anything else; a missing, forged or reused token is a
   409 and nothing is signed, released or notified.
2. **Refresh by GET.** The case page sets `data-reload-on-expiry` to its own
   URL, and the countdown navigates there with `location.replace(url)`.
3. **The address bar shows the case URL** after a declaration
   (`history.replaceState`), so a manual reload is a GET too.
4. **Views only join.** Opening a case calls the custodian with
   `join_only=True`: it joins the open session or fails (409), never opens one.

## Consequences

- Each of the three guards has a negative test in
  `portal/clinician/tests.py::RedeclareLoopTests`, each observed failing with
  its guard removed.
- A clinician who submits the form twice (double click) gets one declaration
  and a 409 explaining nothing was opened. The back button shows a stale form
  whose token is spent; declaring again needs the page reloaded.
- The token is a portal-side control; the facility's own one-time ids
  (assertion, transition event, envelope) still stop any replay that reaches
  the federation.

## Alternatives considered

- **Post/redirect/get for the single-record path** (as the multi-record path
  does) — fixes the reload but not a re-sent POST, and the decrypted record
  would then have to be fetched again on the GET.
- **Disable the auto-refresh** — leaves the stale record on screen after the
  key was rotated.
- **Facility-side dedupe of declarations** — the federation already refuses
  replays; the bug was the portal minting fresh, valid declarations.
