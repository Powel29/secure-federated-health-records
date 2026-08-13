# ADR-0010: Default to a cryptographic-federation model over FHIR/HL7

- **Status:** Accepted (faculty confirmed the crypto model, FHIR not required — 2026-08-13)
- **Date:** 2026-08-12 (proposed), 2026-08-13 (accepted)
- **Deciders:** Team (Powel, Nandini, Ojas, Avaneeth); faculty-confirmed 2026-08-13
- **Task / source:** T03; PROJECT.md §3, §4, §6
- **Affects:** the whole project scope; `identity`, `federation`, `policy`; the novelty claim; Phase 2

## Context

One of the two open faculty questions (T03 Q2) is whether the project should
deliver standards-based interoperability (FHIR/HL7) or a cryptographic federation
model. The two lead to materially different projects: FHIR would make this a
health-informatics interoperability exercise; the cryptographic model makes it a
security project. Work cannot safely proceed into Phase 2 without an answer, but
Phase 0/1 can, so we need a working default now.

## Decision

Default to the **cryptographic federation model**: a simulated federation with
cross-certified facility CAs and a Shamir-over-policy-tree access structure
(ADR-0002), not FHIR/HL7 interoperability. This is our lane and the source of the
novelty claim (PROJECT.md §4). FHIR/HL7 interoperability is explicitly
out of scope (PROJECT.md §6).

## Consequences

- Phase 0 and Phase 1 proceed on this basis immediately; no work is blocked
  waiting on faculty.
- **Confirmed, not provisional.** Faculty confirmed on 2026-08-13 that FHIR/HL7
  is not required, so the cryptographic federation design stands and Phase 2 is
  unblocked. The revision trigger in PROJECT.md §3 did not fire.
- Had faculty answered "FHIR", this decision would have reversed — invalidating
  the federation design, forcing a re-scope of `identity`/`federation`/`policy`
  (T15–T19) and a novelty revisit, superseded by a new ADR before Phase 2. Kept
  here for the record.

## Alternatives considered

- **FHIR/HL7 interoperability** — standards-based, but turns a security project
  into an informatics one and discards our novelty. Rejected as the default;
  revisit only if faculty require it.
- **Wait for faculty before doing anything** — needlessly stalls Phase 0/1 work
  that a FHIR answer would not invalidate. Rejected.
