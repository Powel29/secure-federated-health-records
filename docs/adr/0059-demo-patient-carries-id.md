# ADR-0059: The demo patient carries an ID card; unidentified patients are a stated limitation

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** Avaneeth → all four
- **Task / source:** Clinical review 2026-10-12 (issue 4); follows ADR-0033
- **Affects:** PROJECT.md §1 and §5 (new item 7), ARCHITECTURE.md §5 step 0, `demo/driver.py` Act 3, `docs/explainers/01` and `07`

## Context

The headline scenario is an unconscious patient, but identification is a
name + date-of-birth lookup (ADR-0033) that such a patient cannot answer. The
"John Doe" flow was deferred, so the scenario as written could not happen.

## Decision

Reword the scenario: the patient carries an ID card from which the clinician
reads the name and date of birth. State in the honesty caveats and the paper
that a patient with no ID, or an unknown name or date of birth, cannot be
opened.

## Consequences

- The demo story now matches what the system does.
- The limitation is real and common in emergency departments; it must appear
  in the paper's limitations, not only in the docs.

## Amendment — 2026-10-14

ADR-0060 added a temporary encounter identifier for unidentified arrivals, so
the John Doe *encounter* now exists. The limitation stands for history: no
record can be opened until identity is confirmed and the encounter linked,
and the paper still says the scenario assumes identification.

## Alternatives considered

- **Build the John Doe flow** — needs re-binding assertions to a later
  `patient_id` (ADR-0033 alternatives); too large for the remaining time.
- **Search by national health ID (ABHA)** — still needs an ID, adds a
  directory field; does not remove the limitation.
