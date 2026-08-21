# ADR-0011: Single shared encrypted store, not per-facility storage

Status: Accepted (2026-08-18)
Deciders: Powel (team), relayed decision

## Context
The brief specified a "location-independent, patient-indexed record store on a
semi-trusted cloud" — singular. The deployment topology I later drafted
contradicted this by giving each facility its own records ("facility-a holds
records, facility-b must discover"). The two readings disagreed.

## Decision
Records live in **one shared, semi-trusted, encrypted store**. Facilities hold
keys and certificates, not records; they read ciphertext from the store.
Discovery is a patient-indexed lookup within that store, not a cross-facility
search.

## Consequences
- Simpler to build and demo; matches the brief.
- The store is a single target, but holds only ciphertext, wrapped keys, and a
  coded index — a full compromise yields gibberish. This becomes its own line in
  the threat model (T04) and a stated point in the paper.
- Proxy re-encryption's cross-facility-handoff role disappears (see ADR-0012).
- "Records travel with the patient" softened to "patient-indexed, reachable from
  any facility."
- State machine, break-glass, search, and policy access are unaffected — none
  depended on storage being distributed.
