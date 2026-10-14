---
version: 1
slug: "portal-templates"
primary_target: "portal/templates"
related_targets: ["portal/static/portal/custos.css"]
---

# Surface brief: the three portals (patient / clinician / admin-audit)

Scope: every template under `portal/templates/` plus `portal/static/portal/custos.css`. Mode: Operate.
Audience: examiner watching a projected, narrated demo; personas acted out are patients, clinicians, an auditor.
Job: make the key-lifecycle mechanism visible and legible; break-glass unmistakable; every action traceable.
Constraints: Django templates + plain CSS, minimal JS; portal never decides access; tests assert rendered copy.
Untouched: the case page share cards and chain segment keep their markup and behaviour (restyled only).

## Direction contract

THESIS: Emergency access is a manual call point: one red, framed control the whole system stays quiet around. Refuses the category default of a teal SaaS dashboard of same-size KPI cards, and the hacker-terminal opposite.

OWN-WORLD: White-enamel ground (#f6f5f1), graphite back-box rail (#1e2226), ink #15181b. Signal red #c8102e only for break-glass. Colour quarantined to bordered state plates: ISO safe-green granted, ISO warning-amber pending, slate expired, ink revoked. Action blue #0057a8 only on pressable controls. Trace violet #6b3fa0 only for the correlation flow being followed. Barlow Condensed sign lettering for headings and labels, Barlow body, system mono for hashes. Square corners, 2px ink frames on plates and primary panels, hairline rules elsewhere.
Raised from Lexicon Plate: colour lives only inside bordered plates.
Raised from Split-Flap Concourse: chain and case rows keep fixed columns; state restyles the row, never the grid.
Raised from Orienteering Map: the followed flow rides in one reserved colour on every page.
Raised from Warm Consumer App: action colour only on things you can press.
Raised from Title Card Wall: full hashes open on the focused row; rows show the short form.

STORY: The examiner sees routine access stay calm and grey-framed, then watches a clinician press the one red control; shares fill, the chain commits before share 3, the window counts down and auto-resets by key rotation; the patient and auditor see the same flow in violet.

FIRST VIEWPORT: Graphite rail left (brand, role nav, signed-in identity, a short "access decided by keys" statement). Topbar: h1 screen name; when an emergency is open, a red call-point band with the live countdown. On break-glass: an Identify / Locate / Declare step strip across the top, the red call point (frame, BREAK GLASS label, white pane with what declaring does and the red DECLARE button) left of the reason and justification fields; on the case page the pane is replaced by the clock.

FORM: Call Point (position 7 of the ordered list: EN 54-11 manual call point / ISO 7010 signs). seed: none (unavailable). Disclosed deviation: this CLI version printed only the raw roll key and no SEED REFERENCE line; the raw key is deliberately not recorded. Signature move: the break-glass call point with intact / open (clock in the pane) / reset-by-rotation / failed states. Motion grammar: none beyond a 150 ms ease-out on the pane press and the countdown's final-30-seconds warning; respects reduced motion.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
