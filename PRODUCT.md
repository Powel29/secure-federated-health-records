# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary: the **examiner** (ICT 3121 faculty) watching a live, team-narrated demo of the
cross-facility break-glass scenario, and later reading the paper and the fallback recording.
They judge whether the security mechanism is real, so the mechanism must be visible on screen.

Personas the portals act out, all synthetic (seeded by `deploy/seed_portal.py`):

- **Patients** (`alice`, `david`, `emma`): manage consent, see who accessed their records,
  including any break-glass, read and upload their own records.
- **Clinicians** (`house` ER facility-b, `chase` cardiology facility-a, `cameron`
  endocrinology facility-b): identify a patient, request consent, read under a grant,
  declare break-glass under a 120-second (demo: 60-second) time box.
- **Auditor** (`auditor`): trace any flow by correlation id, verify the hash chain, review
  break-glass cases, check federation health. Read-only.

## Product Purpose

A cryptographically enforced access-control system for encrypted health records in which
consent, revocation and emergency break-glass are one key-lifecycle state machine
(Granted, Revoked, Emergency-open, Expired). The three web portals (ADR-0014) are the
demo UI: they identify users and show data, and make the mechanism observable. Success is
an examiner who leaves convinced that keys and the threshold gate, not the portal, decided
every access.

## Positioning

Logging is a cryptographic precondition of emergency access: break-glass reconstructs an
emergency key from a weighted 3-of-4 Shamir gate (one share for the attending clinician's
custody, one for the patient's home authority as its backup, two for the audit service), and
the audit service releases its shares only after committing a hash-chained entry (ADR-0089). No log entry, no key, no access. Emergency search exists only while the
emergency state lives. The record follows the patient across a simulated federation.

## Operating Context

- Shown live on a classroom projector with a team member narrating, plus a recorded
  fallback. Text must survive projection: size, contrast, and legibility from the back row.
- Runs locally from a clean clone (`deploy/docker-compose.yml` or
  `python -m deploy.run_portal_demo`), loopback only. The demo must work offline.
- Demo scenario: unconscious patient at an out-of-network clinic; clinician identifies by
  name + DOB, discovers records across facilities, declares break-glass, the case page shows
  shares and the chain, access auto-expires; the patient later sees the alert; the auditor
  traces the flow.

## Capabilities and Constraints

- Django templates + plain CSS (`portal/static/portal/`), no front-end build step, minimal
  JavaScript (countdown and expiry only).
- Portals never decide access, never decrypt on their own, never hold keys
  (ADR-0014/0021/0043). UI must never imply otherwise.
- Fail closed: every service or crypto failure renders an explicit denial state.
- Synthetic data only. No real patient data.
- Ownership: patient portal (Avaneeth), clinician (Nandini), admin/audit (Ojas). Cross-owner
  changes go through review and an ADR.
- Portal tests (`portal/*/tests.py`) assert on rendered content; copy changes must keep
  them green.
- Out of scope: FHIR/HL7 interoperability, ML anomaly detection (PROJECT.md §6).

## Brand Commitments

None binding. The current name "CUSTOS" and its Classical theme may be replaced.

## Evidence on Hand

- Seeded synthetic dataset (`demo/seed_data.py`) and portal personas (`deploy/seed_portal.py`).
- Real system behaviour: audit chain, share states, countdowns, correlation ids, fail-closed
  reasons, all live from the running federation.
- No real users, testimonials, or deployment claims exist; never fabricate any.

## Product Principles

1. Show the mechanism. Shares, chain entries, signatures and state transitions are the
   product's evidence and stay visible, labelled so a non-specialist can follow them.
2. Keys decide, the portal displays. No screen may read as if the portal granted access.
3. Emergency is its own state. Break-glass must be unmistakable from routine use.
4. Fail closed, out loud. Refusals are explicit, specific and honest.
5. Every action is traceable. Anything shown links to its audit evidence.

## Accessibility & Inclusion

WCAG 2.1 AA as the floor; projector legibility raises the practical bar for type size and
contrast.
