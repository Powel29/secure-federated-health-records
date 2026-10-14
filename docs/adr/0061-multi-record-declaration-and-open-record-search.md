# ADR-0061: One declaration for several records; search covers open records only; guardians decide for minors

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** Avaneeth → Nandini (clinician and patient portals), Powel (`breakglass`, `search` wording) → all four
- **Task / source:** Clinical review 2026-10-12 (issues 1, 2, 5, 11, 19), follow-up to ADR-0057 and ADR-0060
- **Affects:** `portal/clinician/views.py` (`breakglass`, `_declare`), `portal/clinician/encounters.py` (`federated_search`), `portal/portal_core/clinical.py` (`expand_search_terms`), `portal/portal_core/notify.py`, `portal/patient/views.py` (`_principal`), `portal/accounts/models.py` (`minors_represented_by`), `portal/config/settings.py` (`ASSERTION_TTL_SECONDS`), ADR-0056, ADR-0057, ADR-0059, ADR-0060

## Context

After ADR-0060 the clinical review still had partial gaps:

- A second clinician at another facility could get 409 if the portal sent
  the break-glass to the clinician's own facility instead of the record's.
- The cross-record search ran a break-glass on every general record of the
  patient, so one search widened access to all of them, each with its own
  notification, without the clinician choosing those records.
- Search was exact-match, so "penicilin" or "hemorrhage" missed records
  indexed as "penicillin" and "haemorrhage".
- Each record needed its own declaration, with the reason and justification
  typed again.
- Notifications showed raw record, facility and reason codes, and a minor
  had no one who could consent or revoke for them.

## Decision

1. **Routing.** The portal sends each break-glass to the discovered record's
   facility. The custodian already routes to the record's node when it can
   read the store, so a viewer anywhere joins the open session (ADR-0057).
2. **One declaration, several records.** The break-glass form takes several
   records (none pre-selected) under one reason and justification. Each
   record still gets its own assertion, threshold, audit entry before
   release, case and patient notification. Nothing is batched in the
   cryptography.
3. **Search opens nothing.** Cross-record search queries only the records
   this clinician currently holds open for the patient, at any facility. It
   lists discovered records that are not open as *unsearched*, so a miss is
   never reported as absence.
4. **Spelling tolerance in the portal.** The typed term is case-folded and
   snapped to the closest entry of a fixed clinical vocabulary
   (`difflib`, cutoff 0.85). The query is then expanded to that entry's
   spelling variants and true synonyms. Drug classes are never expanded:
   "warfarin" does not search "anticoagulant". Every expanded term is a
   separate query through the unchanged token derivation (ADR-0027). This
   adds no new construction.
5. **Notifications** name the record title, facility name and readable
   reason instead of codes.
6. **Guardians decide for minors.** A verified, unexpired, unrevoked
   `guardian` or `parent` link to a patient whose recorded date of birth
   makes them under 18 lets that subject approve, deny and revoke the
   minor's consent in the patient portal. The custodian signs with the
   minor's key, and the `consent.decision` audit event records
   `decided_by`. Next of kin, an unknown date of birth, or an adult patient
   give no authority (404). This amends ADR-0060.

## Consequences

- Searching three open records with an expanded term set issues up to
  three times as many emergency-search requests. Each one is audited, and
  the facility sees more tokens per query (more equality-pattern leakage
  under the same ADR-0027 caveat).
- The vocabulary is a short hand-written list. Terms outside it get
  case-folding only, and a record indexed under a spelling not in any
  synonym group still needs that spelling.
- A multi-record declaration does not show plaintext inline. Each record is
  read by opening its case (ADR-0062), which is one more audited access per
  record.
- Guardian authority is decided in the portal from the directory and
  representative tables. The custodian trusts the portal's service identity
  to name the patient, as it already does for the patient's own login.
  Incapacitated adults still have no proxy; that is a stated limitation.

## Alternatives considered

- **Keep search-opens-everything** — fewer clicks, but it widens access
  without a per-record choice and floods the patient with notifications.
- **Fuzzy or substring search in the encrypted index** — a new searchable
  encryption construction, which is outside the project's specified scheme.
- **Next of kin may consent too** — next of kin are contacts, not legal
  decision-makers for a minor.
