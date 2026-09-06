# ADR-0033: Emergency patient identification via name + DOB search

- **Status:** Proposed
- **Date:** 2026-09-02
- **Deciders:** Team (Powel, Nandini, Ojas, Avaneeth)
- **Task / source:** Gap surfaced against ARCHITECTURE.md §8 and P3-10 — the
  `EmergencyAssertion` is bound to a `patient_id`, but nothing in the plan
  said how the clinician at Facility B obtains that `patient_id` for an
  unconscious patient. New task **P4-8a** slotted under Nandini's clinician
  portal (P4-8).
- **Affects:** `portal/clinician/` (new patient-search view), a new
  `PatientDirectory` model in the portal, ARCHITECTURE.md §8 (break-glass
  sequence gains an explicit step 0), WORKFLOW.md (new P4-8a row), and the
  audit chain (P3-13 gains a `patient.lookup` event type).

## Context

ARCHITECTURE.md §8 defines the `EmergencyAssertion` as *bound* to a specific
`patient_id`. The break-glass sequence in §5 assumes the clinician already
holds that identifier by the time they sign the assertion. The plan never
specified how a clinician at an out-of-network facility obtains the
`patient_id` for an unconscious stranger.

Options ranged from QR-on-wristband (needs hardware and enrolment), to
biometrics (whole subsystem, adds nothing to the novelty claim), to
"John Doe" temporary records (complicates the audit chain — assertions
would need re-binding after identity is confirmed).

The identifier itself already exists as an opaque `patient_id` in the crypto
store's `patients` table ([src/storage/migrations/0001_initial.sql:34](../../src/storage/migrations/0001_initial.sql#L34)),
and PII (name, DOB) is explicitly banned from that table by the ADR-0011 /
ADR-0014 boundary. The portal Django DB is the natural home for PII.

## Decision

Emergency patient identification is a **name + date-of-birth search in the
clinician portal**, backed by a new `PatientDirectory` model in the portal
Postgres schema. The clinician enters a name and DOB, sees candidate
matches, selects one, and the resulting break-glass form is pre-populated
with that patient's `patient_id`.

Load-bearing rules:

1. **PII (given_name, family_name, date_of_birth) lives only in the portal
   Postgres schema.** Never in the crypto store's `patients` table. This
   preserves the ADR-0011 boundary — the shared encrypted store still holds
   only ciphertext, wrapped keys, and opaque identifiers.
2. **The portal `PatientDirectory.subject_id` is the same string as the
   crypto-side `patient_id`.** No mapping table, no translation layer, no
   drift. This matches the existing `Profile.subject_id` convention in
   [portal/accounts/models.py:29](../../portal/accounts/models.py#L29).
3. **Identification is not authorization.** A clinician picking a match
   from the search results releases no key. The break-glass threshold gate
   (P3-5) still runs afterwards, and every subsequent check
   (EmergencyAssertion validation, cert chain, threshold reconstruction,
   log-before-release) is unchanged.
4. **Ambiguous matches show every candidate.** If two rows match the
   entered name and DOB, both are shown; the clinician chooses. Auto-selecting
   the first would be a wrong-patient hazard we refuse to build in.
5. **Every lookup is logged.** The search itself is a `patient.lookup`
   event in the audit chain (P3-13-style), including whether a match was
   selected and which `patient_id` was carried forward into the assertion.
   A lookup that yielded nothing is still logged.

## Consequences

**Commits us to:**

- A new `PatientDirectory` model in the portal (given_name, family_name,
  date_of_birth, subject_id) and the seeding of it alongside the crypto
  store's synthetic patients.
- A new clinician-portal search view (P4-8a, ~4h under Nandini) and an
  update to the existing break-glass declaration flow to accept a
  pre-populated `patient_id`.
- A new `patient.lookup` audit event type — Ojas needs to add this to the
  event enum in P3-13 while wiring the audit chain.
- Step 0 added to the ARCHITECTURE.md §8 break-glass sequence so future
  readers see the identification precondition instead of the current
  implicit assumption.

**Makes easy:**

- Demo scenario: the unconscious-patient-at-Facility-B story now has a
  believable UI path, not "the clinician types in `pat-042` from memory."
- Paper narrative: identification and authorization can be presented as
  distinct steps with distinct threat models, which strengthens the novelty
  framing.

**Makes hard / honest downsides:**

- Name + DOB in a portal database is PII. This scoped it to synthetic data
  only (already the project rule per CLAUDE.md and PROJECT.md §6.4), but
  the paper's "Limitations" section should acknowledge that in a real
  deployment this store would be a target and would need its own
  encryption-at-rest and access controls.
- Ambiguous-match handling widens the wrong-patient hazard versus a
  hardware token. This is the price of skipping wristbands and biometrics.
- A malicious portal-authenticated clinician can enumerate patients by
  searching. This is bounded to the portal (no key material), audit-logged,
  and out of scope for the crypto novelty; state it as a portal-layer
  limitation.

**Follow-ups / debts:**

- Rate-limit patient searches at the portal layer to blunt bulk
  enumeration. Not a Phase-3 blocker; slot into the strictness pass or
  P5-1.
- The "John Doe" flow (temporary record when the patient cannot be
  identified) is explicitly deferred. If we implement it later, the ADR
  supersedes-line here should point to that follow-up ADR.

## Alternatives considered

- **QR-on-wristband as the primary identifier.** Cleanest UX, but adds
  hardware scope (patient enrolment, wristband issuance, scanner in the
  clinician portal). Contributes nothing to the novelty claim; rejected as
  out of scope.
- **Biometrics (fingerprint or face).** Most robust for unconscious
  patients, but a whole subsystem (enrolment, matching, template storage,
  liveness). Way over budget; rejected.
- **John Doe / unknown-patient flow as the primary path.** Would let
  clinicians begin break-glass without identification and merge into the
  real record later. This forces the audit chain to support re-binding of
  assertions to a later-resolved `patient_id`, which pushes complexity into
  P3-3 and P3-13. Deferred — may return as a fallback path in a future ADR.
- **Storing name + DOB in the crypto store's `patients` table.** Would
  make lookup one query, but breaks the ADR-0011 / ADR-0014 boundary that
  the store holds no readable PII. This boundary is load-bearing for the
  novelty claim; rejected outright.
