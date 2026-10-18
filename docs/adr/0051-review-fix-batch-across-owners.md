# ADR-0051: Land the no-decision review fixes as one batch on `full-deploy`, across module owners

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Avaneeth → each module owner reviews their part → all four
- **Task / source:** Review fix list "Fixes that need no decisions" (`docs/review/2026-10-07-fix-proposals.md`); CLAUDE.md "One owner per `src/` module"; CONVENTIONS.md §3
- **Affects:** every module the batch touches; see the review doc's status table for the item-by-item list

## Context

About two-thirds of the fixes that need no design decision sit in modules
owned by Powel (lifecycle, breakglass, shamir, crypto_core, consent, wire,
tests/security), Ojas (audit, authority, custodian, admin portal) or Nandini
(search, accounts, clinician portal, bench). The standing rule is that only a
module's owner edits it.

## Decision

Avaneeth implemented the whole batch on `full-deploy` rather than splitting it
into per-owner proposals or branches. Each owner reviews the changes in their
directories before merge and records approval in the PR, exactly as N16 asks
for 638c2c6 and 9721387. Nothing here changes `src/contracts/`.

## Consequences

- One coherent change set: the cross-cutting fixes (compare-and-set state,
  trust anchors, audit sink) land together instead of in a dependency chain.
- It is a deliberate exception to the one-owner rule; the owner reviews are
  the control that replaces it, and they must happen before merge.
- New module `src/custodian/` (client-side key-agent crypto moved out of
  `api/`, F33) needs an owner; Ojas owns the custodian service, so the default
  is Ojas.

## Alternatives considered

- **Per-owner proposal patches** — keeps the rule, but each owner re-derives
  context and the cross-module fixes wait on each other.
- **Per-owner branches** — same review outcome, more merge work.
