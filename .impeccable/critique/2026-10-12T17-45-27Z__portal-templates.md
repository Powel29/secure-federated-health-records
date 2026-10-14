---
target: the website (three portals)
total_score: 20
max_score: 40
na_heuristics: 
p0_count: 0
p1_count: 3
target_identity: "file:C:\\Users\\Tejas\\Desktop\\IS project\\secure-federated-health-records\\portal\\templates"
timestamp: 2026-10-12T17-45-27Z
slug: portal-templates
---
Method: dual-agent (A: design review, B: detector + browser evidence)

Score 20/40 (Acceptable). H1 3, H2 1, H3 2, H4 2, H5 2, H6 2, H7 1, H8 2, H9 3, H10 2.

Specificity: content specific, visuals generic (ported "Classical" theme). Break-glass has no visual language; brass means everything.
Detector: CLI 0 findings INVALID (cannot resolve {% static %}; custos.css unread). Browser overlay 132 findings on 6 pages: undersized-ui-text ~56 (10px kickers/tags/sidebar), low-contrast ~51 (#7d7979 3.8:1; accent #b68235 3.0:1 on every btn-primary), tiny-text ~15, side-tab 6, placeholder 2, line-length 1. FPs: em-dash (audit log separators), nested-cards (.chain inset).

Priority issues:
- [P1] Break-glass neither looks nor guards like an emergency: reason select silently defaults to first option into signed assertion (clinician/breakglass.html:56); optional justification with realistic placeholder (:62); no emergency CTA on clinician home; 4 round trips, no stepper. Fix: empty required option, required justification, --color-emergency token, stepper, home CTA. (harden, colorize)
- [P1] Patient portal speaks protocol: raw actors/detail strings, IDs not names, ADR citations, "Decrypt via owner attribute". Fix: plain-sentence event layer, <details> technical record, plain lifecycle words. (clarify)
- [P1] Accessibility at token level: contrast 3.0/3.8:1, no h1/h2 anywhere, no skip link, silent timer + unannounced auto-reload, unlabelled controls, no fieldset/legend. (audit, typeset)
- [P2] Cormorant old-style numerals: "o"/"I" for 0/1 in stats, clock, BG-0001. Fix lining-nums tabular-nums. (typeset)
- [P2] Mobile: sidebar stacks ~650px above content; Sign assertion at y~1490; history table hides Event column. (adapt)

Personas: clinician under pressure, Jordan (patient), Sam (SR/keyboard), Alex (power user) - see chat report.
Minor: seq gap unexplained in trace; PASS uses brass not --color-ok; expired case search only opacity-dimmed; hard-coded sidebar status; unused unread badge; wrong crumb on record/upload; Google Fonts third-party; no dark theme.
Questions: what does brass mean / what is emergency colour; patient vs examiner audience; one-screen emergency flow; what can Alice do after notification.
