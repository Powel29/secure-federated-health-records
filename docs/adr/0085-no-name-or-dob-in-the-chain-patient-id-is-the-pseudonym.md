# ADR-0085: No name or date of birth in the audit chain; `patient_id` is the chain's pseudonym

- **Status:** Proposed
- **Date:** 2026-10-19
- **Deciders:** Ojas (proposal) → Nandini (`portal/clinician`), portal_core owner (`portal/portal_core/notify.py`), Avaneeth (`api/hospital.py`), Powel (`tests/security`) → all four (amends ADR-0038 §3)
- **Task / source:** whole-project check, 2026-10-19 (finding 1)
- **Affects:** `portal/clinician/views.py` (`patient.lookup` event), `portal/portal_core/notify.py` (`query_hash`), `src/audit/events.py` (`patient_id_hash`, `log_federation_discovery`), `src/api/hospital.py` (federation-discovery event), `tests/audit/test_events.py`, `tests/security/test_phase3_denial_federation_audit_security.py`, ADR-0038, `ARCHITECTURE.md` §8, `PROJECT.md` §5

## Context

`ARCHITECTURE.md` §8 (and ADR-0011) say PII (name, date of birth) lives only
in the portal DB, never in the crypto store. The audit chain is in the store
(`audit_log`). Two hashes were meant to keep patient identity out of it; the
check found that neither does.

1. **`query_hash` puts PII in the chain.** Every `patient.lookup` entry carries
   `query_hash = SHA-256(family ‖ 0x1f ‖ given ‖ 0x1f ‖ dob)`, lower-cased and
   unsalted (`portal_core/notify.py:175`). Names and dates of birth have very
   little entropy: anyone who can read `audit_log` (the auditor, the store
   operator, a store compromise) can try a list of common names against
   ~36,500 dates and recover what a clinician typed, including searches for
   people who are not patients here. Nothing reads `query_hash`; it is written
   and never used.
2. **`patient_id_hash` hides nothing.** `federation.discovery` entries store
   `SHA-256(patient_id)` instead of `patient_id` (ADR-0038 §3, "so the chain is
   not a plaintext index of patient identities"). But:
   - ids like `pat-101` can be enumerated, so the hash reverses at once;
   - the same entry lists the `record_ids`, and the store's `records` table maps
     each record to its `patient_id` in a plain column;
   - other entries already store the raw `patient_id`: the share-3 release
     (`api/audit_service.py:498`), custodian events, and the portal's
     `patient.notification` and `patient.lookup` (`candidate_ids`,
     `selected_patient_id`).

   So `test_sec_federation_discovery_event_never_stores_raw_patient_id` proves
   a property of one event type that the system as a whole does not have, and
   ADR-0038 and the `log_federation_discovery` docstring overstate it.

The underlying fact is that the store is patient-indexed by design
(ADR-0011): `patient_id` is the federation's pseudonym for a person, and only
the portal DB links it to a name. The chain cannot avoid naming that pseudonym
while it records who opened which patient's records, and the break-glass
release entry must name it, because the signed assertion is bound to it.

## Decision

1. **Remove `query_hash` from `patient.lookup`, and delete the helper.** The
   entry keeps `clinician_id`, `facility_id`, `candidate_count`,
   `candidate_ids` and `selected_patient_id`. That still meets ADR-0033 ("every
   identification is in the chain", misses included as `candidate_count: 0`),
   and records *that* a lookup happened and *whom* it surfaced, but nothing
   about what was typed. No replacement field.
2. **Name patients by `patient_id` everywhere in the chain.**
   `federation.discovery` logs `patient_id` like every other event;
   `patient_id_hash` is removed. This changes no protection, because there was
   none, and it makes per-patient audit questions answerable with one query.
3. **State the real property.** The chain is **pseudonymous, not anonymous**:
   it holds no name, date of birth or other portal PII, and it names patients
   only by `patient_id`, which links to a person only through the portal DB.
   `patient_id` must never be derived from PII; in a real deployment it is a
   random identifier issued at enrolment (the demo's sequential `pat-101` is
   synthetic). This goes into `ARCHITECTURE.md` §8 next to the PII rule and as
   a limitation in `PROJECT.md` §5: whoever reads the chain learns which
   pseudonymous patient was accessed, by whom and when.
4. **Replace the misleading test with the invariant that matters.**
   - The portal is the only writer that sees names and dates of birth, so the
     new negative test sits there:
     `portal/clinician/tests.py::IdentifyTests::test_lookup_entry_records_nothing_about_what_was_typed`.
     It runs two lookups that surface the same candidates with different
     text (and two misses with different text), and requires each pair to
     log identical entries, so no field may depend on what was typed, a hash
     of it included. It also checks that no typed name or date, in several
     formats, appears in anything sent to the audit service. With
     `query_hash` restored it fails (checked 2026-10-19); the old check that
     "Vance" is absent stayed green with the hash in place.
   - `test_sec_federation_discovery_event_never_stores_raw_patient_id`
     becomes `test_sec_federation_discovery_event_carries_identifiers_only`,
     which pins the exact field set, so an extra field (a key, a hash, a
     name) fails it.

No cryptography is added or changed: this removes one hash and one hashed
field.

## Consequences

- `ARCHITECTURE.md` §8's "no PII in the crypto store" becomes true. Today it
  is false for every lookup.
- The `federation.discovery` field changes from `patient_id_hash` to
  `patient_id`. Every run is a fresh bootstrap (ADR-0039), so there is no
  stored chain to migrate; any reader of the old field (only tests today)
  changes with it.
- An auditor can no longer tell that two lookups used the *same* query text.
  Nothing used that, and the candidate ids already show which patients were
  surfaced.
- The paper must say "pseudonymous" and must not claim the chain hides who
  was accessed.
- Four owners touch five files, so this is one coordinated PR (like ADR-0051),
  with each owner reviewing their own directory.

## Alternatives considered

- **Keyed pseudonyms (an HMAC or HKDF of `patient_id`, and of the query,
  under a key the chain's readers do not hold).** Rejected for this build. It
  is a construction `ARCHITECTURE.md` §3 and §8 do not specify, so the
  crypto-implementation rule forbids adding it without a team decision. It
  also buys nothing unless the store's own `patients` and `records` index and
  the signed assertion move to the same pseudonym, since the raw id sits in
  plain columns beside the chain. Reopen it, as its own ADR, if the team wants
  the store operator unable to link accesses to patients.
- **Keep both hashes and correct only the documentation.** Rejected: the
  `query_hash` still leaks PII however it is described, and a hashed id in one
  event type beside raw ids in the rest invites an examiner to ask what it
  protects.
- **Keep `query_hash` but salt it with a per-entry random salt.** Rejected: a
  per-entry salt makes it useless for correlation, which was its only
  purpose, and nothing reads it.
