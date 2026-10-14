# ADR-0055: Portal redesign: the "Call Point" design system

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Avaneeth (proposal, patient portal owner) → Nandini (clinician portal), Ojas (admin & audit portal) to review
- **Task / source:** Impeccable design critique of the three portals (`.impeccable/critique/`), scored 20/40; ADR-0014 (portals), ADR-0043 (Custos styling)
- **Affects:** `portal/static/portal/custos.css`, `portal/static/portal/fonts/`, every template under `portal/templates/`, `portal/portal_core/display.py` (new `humanize_code` filter, registered as a template builtin in `portal/config/settings.py`), `portal/patient/views.py` (plain-language history sentence)

## Context

A design critique of the three portals found:

- **Break-glass looked like every other screen.** The brass accent was used for the active nav item, every button, the PASS verdict and break-glass alike.
- **The reason code had a silent default.** The break-glass `<select>` had no empty option, so a hurried clinician could sign `cardiac_arrest` into the assertion without choosing it.
- **Text failed contrast.** The primary button text was 3.0:1 and secondary text 3.8:1.
- **No page had an `h1` or `h2`.**
- **Old-style numerals misread.** Cormorant's numerals turned "0" into "o" on the clock and the stats.
- **The mobile sidebar buried content.** On phones it stacked about 650px of chrome above the page content.

The demo is projected live for the examiner. That needs large, high-contrast text, and it must work offline.

## Decision

Replace the "Classical" theme (Cormorant / Lora / brass) with a new design system named after the manual fire-alarm "call point" (EN 54-11 / ISO 7010):

- **Ground and type.** A white-enamel ground, a graphite rail and sign lettering (Barlow and Barlow Condensed, OFL, self-hosted).
- **Red means break-glass.** Signal red is used for break-glass and nothing else. The declare action is a red, framed call point; on the case page the countdown clock replaces the declare button inside it. When the window expires, the panel goes slate ("reset, key rotated").
- **Colour only marks state, action or the followed flow.** Colour appears inside bordered state labels (ISO safe green for granted, warning amber for pending, slate for expired, ink for revoked), on controls you can press (action blue), and on the correlation flow being followed (trace violet).
- **Break-glass guards.** The reason code now needs an explicit choice, the justification is required, no record is pre-selected, and a three-step strip runs Identify → Locate → Declare. Clinician home gets a "Start emergency access" entry point.
- **Accessibility.** `h1`/`h2` hierarchy, a skip link, labelled controls, `fieldset`/`legend`, `role="timer"` plus a polite announcement at 30 seconds, and a visible banner before the expiry reload.
- **Small screens.** On phones the rail collapses to a menu and tables stack into labelled rows.
- **Name.** The product name stays CUSTOS (`PORTAL_PRODUCT_NAME`).

## Consequences

- One stylesheet governs all three portals. The clinician and admin templates (Nandini's and Ojas's) changed in this PR and need their owners' review before merge.
- Behaviour and access are unchanged: the portal still decides nothing (ADR-0014). The only behaviour changes are browser-side: required fields, no pre-selected record, confirm dialogs on Sign grant and Revoke, and a 5-second announced reload at expiry instead of 1.5 seconds.
- **Server-side gap.** Justification is required only in the HTML; the view still accepts an empty one. Server enforcement would be a clinician-view change for Nandini.
- **Font licence.** The font files (about 90 KB) are committed with their OFL licence.
- **Downside: the system depends on discipline.** Red must not drift into other uses, because a stray red badge breaks the emergency signal. `DESIGN.md` records the rule.
- **Not seen live.** The open break-glass state (red topbar band, live clock in the call point) was not captured, because producing one writes to the shared audit chain. Verify it in the next demo run.

## Alternatives considered

- **Controlled Drugs Register** (numbered entries with witness-signature slots that fill as shares arrive). Strong fit, but this ledger look is where most designs in this category land, and ruled paper tends to replace real tables.
- **Airport wayfinding (yellow signs)**. Clear step flow, but it reads as an airport rather than a hospital, and yellow everywhere is tiring on a projector.
- **The standard clinical SaaS look** (white cards, teal, Inter). Interchangeable with any health dashboard, and it hides the mechanism the examiner came to see.
- **Keep Classical and patch it** (fix contrast and numerals only). Rejected because break-glass would still have no visual language of its own.
