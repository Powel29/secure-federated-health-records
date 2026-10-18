# ADR-0062: An open case shows its record whenever the page is viewed

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** Avaneeth → Nandini (clinician portal) → all four
- **Task / source:** Clinician usability request; amends the portal half of ADR-0057
- **Affects:** `portal/clinician/views.py` (`case_detail`, `_show_record`), `portal/templates/clinician/case.html`, ADR-0057, ADR-0061

## Context

After break-glass the decrypted record appeared on the declaring response
only. Opening the case later showed the shares and the chain but no record
until the clinician pressed "View record again". In an emergency that is
an extra step every time, and a multi-record declaration (ADR-0061) showed
no record at all until each case was opened and the button pressed.

## Decision

Whenever an open case's page is rendered (opening it, reloading it, or
after an emergency search on it), the portal fetches the record through
the same join as before (ADR-0057). That means a fresh one-time assertion,
the 2-of-3 threshold, and the audit entry committed before share 3 is
released, with no new transition and no extension of the window. The
"View record again" button is removed. Expired, failed or out-of-window
cases fetch nothing. The payload is still never stored, and every response
is `Cache-Control: no-store`.

## Consequences

- Every page load of an open case is one audited access in the case's
  chain segment, so reloads and searches add audit entries and PRE
  re-wraps.
- A GET now has a side effect (an audit entry and a key release). A browser
  prefetch of a case URL would count as a view; the portal does not
  advertise prefetch hints.
- An audit or custodian outage shows the error on the case page (403/503)
  instead of only after a button press.

## Alternatives considered

- **Keep the button** — one extra click per view, per record, in an
  emergency.
- **Cache the plaintext in the session** — the portal would store
  decrypted records, breaking ADR-0014/0043.
