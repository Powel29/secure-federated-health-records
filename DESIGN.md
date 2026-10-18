---
name: Custos
description: Federated break-glass EHR portals built as a manual call point; one red control, a quiet system around it.
colors:
  enamel: "#f6f5f1"
  surface: "#ffffff"
  sunk: "#ecebe6"
  ink: "#15181b"
  ink-2: "#4a525a"
  line: "#d3d0c8"
  graphite: "#1e2226"
  graphite-2: "#2a2f34"
  rail-text: "#e6e4df"
  rail-muted: "#a8adb3"
  signal-red: "#c8102e"
  signal-red-deep: "#9c0c24"
  signal-red-wash: "#fbe8eb"
  safe-green: "#00805a"
  safe-green-wash: "#e3f2ec"
  warning-amber: "#f2b705"
  expired-slate: "#5b6670"
  action-blue: "#0057a8"
  action-blue-deep: "#00447f"
  trace-violet: "#6b3fa0"
  trace-violet-wash: "#f1ebf8"
typography:
  display:
    fontFamily: "Barlow Condensed, Bahnschrift, DIN Alternate, Arial Narrow, sans-serif"
    fontSize: "36px"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "0.005em"
  headline:
    fontFamily: "Barlow Condensed, Bahnschrift, DIN Alternate, Arial Narrow, sans-serif"
    fontSize: "24px"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "0.005em"
  title:
    fontFamily: "Barlow Condensed, Bahnschrift, DIN Alternate, Arial Narrow, sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: 1.1
  body:
    fontFamily: "Barlow, Bahnschrift, Segoe UI, system-ui, sans-serif"
    fontSize: "17px"
    fontWeight: 400
    lineHeight: 1.5
    fontFeature: "lnum"
  label:
    fontFamily: "Barlow Condensed, Bahnschrift, DIN Alternate, Arial Narrow, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    letterSpacing: "0.04em"
  plate:
    fontFamily: "Barlow Condensed, Bahnschrift, DIN Alternate, Arial Narrow, sans-serif"
    fontSize: "14px"
    fontWeight: 700
    lineHeight: 1.35
    letterSpacing: "0.04em"
  clock:
    fontFamily: "Barlow Condensed, Bahnschrift, DIN Alternate, Arial Narrow, sans-serif"
    fontSize: "64px"
    fontWeight: 700
    lineHeight: 1
    fontFeature: "tnum"
  mono:
    fontFamily: "ui-monospace, Cascadia Mono, Consolas, SF Mono, Menlo, monospace"
    fontSize: "14px"
    fontWeight: 400
    fontFeature: "tnum"
rounded:
  none: "0px"
spacing:
  s-1: "4px"
  s-2: "8px"
  s-3: "12px"
  s-4: "16px"
  s-5: "24px"
  s-6: "32px"
  s-7: "48px"
components:
  button-primary:
    backgroundColor: "{colors.action-blue}"
    textColor: "{colors.surface}"
    typography: "{typography.title}"
    rounded: "{rounded.none}"
    padding: "8px 18px"
    height: "44px"
  button-primary-hover:
    backgroundColor: "{colors.action-blue-deep}"
    textColor: "{colors.surface}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "8px 18px"
    height: "44px"
  button-secondary-hover:
    backgroundColor: "{colors.sunk}"
  button-strong:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.surface}"
    rounded: "{rounded.none}"
    padding: "8px 18px"
    height: "44px"
  button-emergency:
    backgroundColor: "{colors.signal-red}"
    textColor: "{colors.surface}"
    rounded: "{rounded.none}"
    padding: "8px 18px"
    height: "56px"
  button-emergency-hover:
    backgroundColor: "{colors.signal-red-deep}"
  button-disabled:
    backgroundColor: "{colors.sunk}"
    textColor: "{colors.expired-slate}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.none}"
    padding: "8px 12px"
    height: "44px"
  tag:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink-2}"
    typography: "{typography.plate}"
    rounded: "{rounded.none}"
    padding: "1px 8px"
  tag-ok:
    textColor: "{colors.safe-green}"
  tag-warn:
    backgroundColor: "{colors.warning-amber}"
    textColor: "{colors.ink}"
  tag-expired:
    textColor: "{colors.expired-slate}"
  tag-revoked:
    textColor: "{colors.ink}"
  tag-fail:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.surface}"
  tag-emergency:
    backgroundColor: "{colors.signal-red}"
    textColor: "{colors.surface}"
  tag-trace:
    textColor: "{colors.trace-violet}"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.none}"
    padding: "24px"
  callpoint:
    backgroundColor: "{colors.signal-red}"
    textColor: "{colors.surface}"
    rounded: "{rounded.none}"
    padding: "16px"
  callpoint-reset:
    backgroundColor: "{colors.expired-slate}"
  callpoint-failed:
    backgroundColor: "{colors.ink}"
  rail:
    backgroundColor: "{colors.graphite}"
    textColor: "{colors.rail-text}"
    width: "264px"
  rail-link-current:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
---

# Design System: Custos

## Overview

**Creative North Star: "The Call Point"**

The three portals (patient, clinician, auditor) are built like an EN 54-11 manual call point mounted on a white enamel wall. Everything routine (consent, reads, audit rows) stays quiet, grey-framed and lettered like safety signage. One control is red: the break-glass call point, with its framed label, its white pane, and the DECLARE button behind it. The whole system stays calm around that one control, so when it is pressed the change cannot be missed from the back of a projected classroom.

The material is enamel ground, a graphite back-box rail, ink lettering and 2px ink frames. Colour does not decorate. It appears only where it carries state (a bordered plate), where it can be pressed (action blue), or where it marks the flow being followed (trace violet). Type is sign lettering: Barlow Condensed for headings, labels and plates, Barlow for running text, system mono for hashes and identifiers. Numerals are lining and, in clocks, tables and chains, tabular.

Density is medium and built for projection: 17px body, 44px minimum control height, generous 24px gaps between panels. Motion is almost absent: a 120ms ease-out on button press and background change, a stepped blink on the countdown's last seconds, and none at all under reduced motion.

**Key Characteristics:**
- One red control per screen; signal red means break-glass and nothing else.
- Colour lives inside bordered state plates, on pressable controls, or on the followed flow.
- Square corners everywhere; 2px ink frames on plates and primary panels, hairlines elsewhere.
- Condensed sign lettering in uppercase for labels and plates, never for running text.
- Fixed-column rows: state restyles a row, never the grid.

## Colors

A quiet enamel-and-ink palette with ISO 7010 safety colours held in reserve for state, one blue for action and one violet for tracing.

### Primary
- **Signal Red** (#c8102e): break-glass only. The call point frame, the DECLARE button, the open-emergency band in the topbar, the countdown clock, the emergency nav link when current, the emergency state plate, the red wash on committed break-glass chain rows and emergency notices. The brand mark carries a red ring because the mark is a miniature call point; that is the only non-control use. Deep red (#9c0c24) is its hover; red wash (#fbe8eb) backs emergency notices and highlighted chain rows.

### Secondary
- **Action Blue** (#0057a8): anything you can press. Primary buttons, text links, ghost buttons, the focus ring, the input caret, disclosure summaries. Hover deepens to #00447f.

### Tertiary
- **Trace Violet** (#6b3fa0): correlation ids and the flow being followed. The "Following flow" marker in the page header, correlation-id links, trace plates, and the violet wash (#f1ebf8) on a targeted table row.

### State plates (ISO 7010)
- **Safe Green** (#00805a): granted, verified, share held. Plate outline, the filled share socket, the OK verdict.
- **Warning Amber** (#f2b705): pending. Always a filled plate with ink text (pending plates, nav counts, the "New" marker on unread notifications), never amber text on white.
- **Expired Slate** (#5b6670): expired, dead tokens, the reset call point, info notices, disabled controls.
- **Ink as state** (#15181b): revoked (ink outline, struck through) and failed (solid ink fill, white text).

### Neutral
- **White Enamel** (#f6f5f1): page ground and the topbar.
- **Plate White** (#ffffff): cards, panels, plates, inputs.
- **Sunk Enamel** (#ecebe6): quotes, disabled controls, secondary-button hover.
- **Ink** (#15181b): text, 2px frames, the strong button, the current step.
- **Ink Grey** (#4a525a): secondary text, labels, table heads.
- **Hairline** (#d3d0c8): 1px rules between rows and around quiet panels.
- **Graphite** (#1e2226) with Graphite Hover (#2a2f34): the rail and the auth backdrop. Rail text #e6e4df, rail muted #a8adb3.

### Named Rules
**The One Red Rule.** Signal red belongs to break-glass. If an element is red and pressing it, reading it or seeing it does not concern an emergency, it is wrong.

**The Plate Rule.** Colour lives only inside a bordered state plate, on a pressable control, or on the followed correlation flow. Coloured text loose on a page, tinted card backgrounds and coloured section headings are not part of this system.

**The Press Rule.** Action blue appears only on things that respond to a click or tap.

## Typography

**Display Font:** Barlow Condensed 600/700 (self-hosted woff2, OFL; falls back to Bahnschrift, DIN Alternate, Arial Narrow)
**Body Font:** Barlow 400/600 (self-hosted woff2, OFL; falls back to Bahnschrift, Segoe UI, system-ui)
**Label/Mono Font:** system mono (ui-monospace, Cascadia Mono, Consolas) for hashes, ids, correlation ids and `x` share values

**Character:** Road-sign and safety-placard lettering over a plain, open grotesque. The condensed face does the naming and the state-calling; the regular face does the explaining.

### Hierarchy
- **Display** (700, 36px, 1.1): the screen name in the topbar; 30px below 860px, 32px on auth cards.
- **Headline** (700, 24px, 1.1): section and card titles.
- **Title** (600, 20px, 1.1): sub-sections. Record titles, candidate names, share holders and notification titles run 21-22px at 700.
- **Body** (400, 17px, 1.5): running text, capped at 64ch. Small text is 15-16px; the floor is 14px (13px only for mono ids and full hashes).
- **Label** (600, 15px, 0.04em, uppercase): fact labels, table heads, chain heads, rail section names, step numbers.
- **Plate** (700, 14px, 0.04em, uppercase): state plates. The call point label runs 22px at 0.14em.
- **Clock** (700, 64px in the call point, 44px elsewhere, tabular): the break-glass countdown; 52px below 600px.

### Named Rules
**The Sign Lettering Rule.** Uppercase belongs to condensed labels, plates and the call point label. Running text and headings stay sentence case.

**The Lining Numerals Rule.** All numerals are lining; clocks, tables, chains and counts are tabular so digits never shift.

## Layout

A fixed graphite rail (264px, sticky, full height) carries brand, role navigation, signed-in identity and a short "a login identifies you; keys decide access" statement. The main column has a topbar (screen name left, flow marker or open-emergency band right, 2px ink rule beneath) and a content column capped at 1440px with 24px gaps between blocks and 32px side padding.

Spacing runs on a 4px base: 4, 8, 12, 16, 24, 32, 48. Panels sit in auto-fit grids (two columns from 440px, three from 210px). On break-glass the call point takes a 280-380px column beside the form; it stacks under 1100px.

Responsive behaviour:
- **Below 860px** the rail collapses into a sticky top bar: brand left, a "Menu" disclosure right that drops the full nav, identity and sign-out as a graphite panel. Form grids and the steps strip go to one column; content padding drops to 16px.
- **Below 600px** tables marked for stacking become label/value blocks (condensed uppercase label in a 88px gutter, 2px ink rule between records); the share strip stacks; the chain drops its head column and keeps seq + event.

**The Fixed Column Rule.** Chain rows and case rows keep their column grid in every state. A highlight, a hover or a target changes the row's background or adds a plate; it never moves a column.

## Elevation & Depth

Mostly flat. Depth comes from frames and ground contrast (white plates on enamel, graphite rail against both), with one soft ambient shadow lifting cards and record cards off the wall. The call point is the only element with a structural shadow: an inset bottom lip that makes it read as a mounted box. The auth card floats over the graphite backdrop with a deep shadow.

### Shadow Vocabulary
- **Wall** (`box-shadow: 0 2px 6px rgba(21, 24, 27, 0.08)`): cards, record cards, the call point.
- **Box lip** (`box-shadow: inset 0 -6px 0 rgba(0, 0, 0, 0.18)`): the call point frame only.
- **Auth float** (`box-shadow: 0 16px 40px rgba(0, 0, 0, 0.35)`): the sign-in and enrolment card over graphite.

### Named Rules
**The Frame Over Shadow Rule.** Importance is shown by a 2px ink frame, not a deeper shadow. Framed plates (steps, shares, chain, verify, notices, plaintext) carry no shadow at all.

## Shapes

Square corners throughout (0px radius, including inputs). Two border weights: a 2px ink frame for state plates, primary panels, selected rows and the topbar rule; a 1px hairline (#d3d0c8) for quiet panels, row dividers and table cells. Strips (steps, share sockets) are one framed box divided by 2px ink rules, not separate cards. Icons are stroked 24px-grid glyphs with square caps and mitred joins at 2.25 stroke, drawn inline from one partial.

## Components

### Buttons
Sign-lettered, square, at least 44px tall.
- **Shape:** square corners (0px), 2px border, Barlow Condensed 700 at 18px.
- **Primary:** action blue fill, white text, 8px 18px padding.
- **Secondary:** white with 2px ink border; hover fills sunk enamel.
- **Strong:** solid ink, for decisive non-emergency actions.
- **Emergency:** signal red fill, wider tracking (0.06em); 22px and 56px tall inside the call point. Never used outside break-glass.
- **Ghost:** underlined action-blue text, 36px tall, for low-weight actions.
- **States:** press shifts 1px down (120ms ease-out); disabled is sunk enamel with slate text and a not-allowed cursor; focus is a 3px action-blue outline offset 2px.

### State plates (tags)
- **Style:** inline condensed uppercase at 14px/700, 1px 8px padding, 2px border in the text colour, white ground.
- **Variants:** granted green outline; pending amber fill with ink text; expired slate outline; revoked ink outline struck through; failed solid ink; emergency solid red; trace violet outline; quiet (1px border, 600 weight) for neutral counts; id (1px, mono 13px, sentence case) for real case numbers.

### Cards / Containers
- **Corner Style:** square.
- **Background:** plate white on enamel.
- **Shadow Strategy:** the Wall shadow on quiet cards; none on framed ones.
- **Border:** hairline by default; 2px ink frame on primary panels.
- **Internal Padding:** 24px (16px below 860px).

### Inputs / Fields
- **Style:** white, 2px grey (#6b7279) border, square, 44px tall, 17px text, blue caret. Labels sit above in 16px/600 body, hints below at 14px.
- **Focus:** border turns action blue plus a 3px translucent blue outline.
- **Disabled:** sunk enamel with slate text.
- **Choice rows:** radio and checkbox rows stack as hairline boxes; the checked row gains a 2px ink frame.

### Navigation
Graphite rail with condensed uppercase section names; links 16px rail text, hover graphite-2, current page inverted to white with ink text and 600 weight. The break-glass link is pale red (#ffb3bf) and turns solid signal red when current. Pending counts are amber filled plates aligned right. Below 860px the rail becomes the top bar with a Menu disclosure.

### The Call Point (signature)
A red mounted box: a condensed uppercase "BREAK GLASS" label with the glass icon, then a white pane (#fcfcfa, 3px white border, 2px dark outline) holding what declaring does and the 56px red DECLARE button. On the case page the pane holds the 64px clock instead. Reset by key rotation turns the frame slate and the clock slate; failure turns the frame ink. The frame carries the box-lip shadow.

### Steps strip
Identify / Locate / Declare as one 2px-framed strip of three cells divided by ink rules. Each cell is a numbered condensed label over an 18px statement. Done steps get a green check, the current step inverts to solid ink with white text, upcoming steps go grey and regular weight. Stacks to one column below 860px.

### Share sockets
The 2-of-3 threshold as one framed strip of three sockets. Each socket opens with a 24px square socket (3px ink outline, filled green when held), then the state plate, the holder name in 22px condensed, the share index, a short note and the mono `x` value. Stacks below 600px.

### Chain table
A 2px-framed list with fixed columns (seq 52px, head 72px, event). Seq and short head hash in mono; full entry hash opens on hover or focus of the row. The committed break-glass entry gets the red wash and an inline red-outlined "Break-glass" plate before its event text; the grid never shifts.

### Verify plate
A framed two-column plate: a large 34px condensed verdict word in a 3px box (green outline for OK, solid ink for failed) beside what was verified and its detail.

### Notices
Framed white bars with a leading icon: success green frame, info slate frame, error ink frame, emergency red frame on red wash.

### Open-emergency band
In the topbar while an emergency is open: solid signal red, white text, uppercase condensed lead, and an inline 24px tabular clock.

## Do's and Don'ts

### Do:
- **Do** keep signal red (#c8102e) to break-glass: the call point, the emergency button, the open-emergency band, the countdown, emergency plates and the committed chain row.
- **Do** put state colour inside a bordered plate with an uppercase condensed label, and fill amber plates with ink text.
- **Do** use action blue (#0057a8) only on links, buttons and focus.
- **Do** carry the followed correlation flow in trace violet (#6b3fa0) on every page that shows it.
- **Do** keep corners square and frame plates and primary panels with a 2px ink border; use hairlines (#d3d0c8) elsewhere.
- **Do** show the short hash in the row and open the full hash on the focused row.
- **Do** keep controls at least 44px tall and body text at 17px for projection.
- **Do** honour reduced motion: no animation, no transition.

### Don't:
- **Don't** use red for errors, destructive non-emergency actions or decoration; failure is ink.
- **Don't** set coloured text loose on the page or tint whole cards to show state.
- **Don't** colour anything blue that cannot be pressed.
- **Don't** put a kicker or eyebrow label above a heading; the heading names the section on its own.
- **Don't** round corners or add hard offset shadows.
- **Don't** let a row's state change its column widths.
- **Don't** use old-style numerals; numerals are lining, and tabular in clocks, tables and chains.
