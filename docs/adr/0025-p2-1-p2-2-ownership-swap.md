# ADR-0025: Swap ownership of P2-1/P2-2 from Avaneeth to Ojas

- **Status:** Accepted
- **Date:** 2026-08-30
- **Deciders:** Ojas, Avaneeth
- **Task / source:** P2-1, P2-2 (WORKFLOW.md "Ownership model" and task table)
- **Affects:** `identity` (C5), `authority` (C6); WORKFLOW.md task table only —
  the rest of the ownership model (Ojas: audit chain, PRE, services, security
  testing; Avaneeth: data plane, remaining identity-layer tasks) is unchanged.

## Context

`WORKFLOW.md`'s ownership model assigns "the data plane and the federation's
identity layer" to Avaneeth, which includes P2-1 (identity and
cross-certification) and P2-2 (attribute issuing). Ojas and Avaneeth mutually
agreed to swap these two specific tasks; Ojas implemented and committed both
on `Phase2/p21/p22` (`src/identity/`, `src/authority/`). This is a reversal of
what WORKFLOW.md states, which the project's standing rule requires logging.

This swap is scoped to P2-1/P2-2 only. It does not carry forward to P2-6
(credential lifecycle) or any other task currently assigned to Avaneeth —
those stay as WORKFLOW.md already lists them unless a separate decision says
otherwise.

## Decision

P2-1 and P2-2 — and the `src/identity/` and `src/authority/` directories for
the purpose of `CONVENTIONS.md` §3's one-owner-per-module rule — are now
Ojas's. WORKFLOW.md's task table is updated accordingly; the "Ownership
model" prose paragraph is left as the general default and not rewritten, since
this is a one-off swap of two tasks, not a change to the standing role split.

## Consequences

- Reviews and future edits to `src/identity/`, `src/authority/` should treat
  Ojas as the owner going forward, not Avaneeth.
- `src/crypto_core/x509_certs.py`, added on the same branch to back the X.509
  chain work, is **not** covered by this swap — `crypto_core` remains
  Powel's per WORKFLOW.md/CONVENTIONS.md §3 regardless of who owns P2-1/P2-2.
  Reviewed and approved by Powel on `phase2/task-review` before this merge.
- Honest downside: task ownership now diverges from the printed "Ownership
  model" paragraph for these two tasks, which could confuse someone reading
  only the prose and not the task table. Mitigated by this ADR and the ✅
  annotations already on the P2-1/P2-2 rows.

## Alternatives considered

- **Leave P2-1/P2-2 attributed to Avaneeth in WORKFLOW.md** despite Ojas
  having implemented them. Rejected: `CONVENTIONS.md` §3's ownership rule
  exists so it's always clear who defends a module in the viva and who
  reviews changes to it; leaving the table wrong would make it silently
  misleading the first time someone checks who owns `src/identity/`.
- **Rewrite the "Ownership model" paragraph** to move the whole identity
  layer to Ojas. Rejected: the swap was agreed for these two tasks only: see
  the answered clarifying question that scoped it to P2-1/P2-2, not the full
  role column.
