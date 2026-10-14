# ADR-0048: One-time declaration token and GET-only expiry refresh in the clinician portal

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** Powel (proposal); Nandini (P4-8 owner) to review; team ratification pending
- **Task / source:** P4-8 clinician portal; live Compose demo (cases opening every 120 s)
- **Affects:** `portal/clinician/views.py`, `portal/templates/base.html`,
  `portal/templates/clinician/breakglass.html`, `portal/templates/clinician/case.html`,
  `portal/templates/clinician/_search_card.html`

## Context

The break-glass declaration renders the case page as the direct response to a
`POST /clinician/breakglass/` (the decrypted record is shown on that response only,
so there is no redirect). The case page refreshed itself at expiry with
`location.reload()`, which re-submits that POST. The portal accepted the
resubmission, so every expiry declared break-glass again: a new signed assertion,
a new audit share release, a new patient notification and a new window. In the
live demo the store showed cases opening exactly 120 s apart.

Separately, emergency search posted the same page back as a full re-render, which
dropped the decrypted record shown above it.

## Decision

1. Every render of the break-glass form mints a fresh one-time token
   (`secrets.token_urlsafe`) into the session and the form. A declare POST must
   carry it; the token is spent on first use, and a missing or reused token is
   refused with 409 before any assertion is signed or share requested.
2. The expiry refresh navigates (GET) to the case's own URL instead of reloading,
   and the declare response rewrites the address bar to that URL
   (`history.replaceState`), so neither the timer nor a manual reload re-POSTs.
3. Emergency search submits in the background and swaps only the search card;
   without JavaScript the form still posts as before.

## Consequences

The 120 s re-declare loop is closed at the server, not only in the browser. A
clinician who really needs a second session declares again from a fresh form,
which is the intended deliberate act. Tests in `portal/clinician/tests.py` cover a
replayed and a token-less declaration; both go red with the check disabled.

Downside: a declare form left open in two tabs only works in the most recently
rendered one, and the decrypted record is still lost on a full page reload; a
"view again during the window" path was considered and deferred (it adds a DEK
re-delivery step `ARCHITECTURE.md` §5 does not specify).

## Alternatives considered

- **Post/redirect/get for the declaration** — fixes reloads, but the redirect
  target cannot show the one-time decrypted record without storing it.
- **Browser-only fix (no reload at expiry)** — removes this trigger but leaves Back
  and manual reload able to re-declare; the server must refuse a replayed form.
- **Refuse a declare while a case for the same record is open** — does not stop a
  re-declare after expiry, which is exactly when the loop fired.
