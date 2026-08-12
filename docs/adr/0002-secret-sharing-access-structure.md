# ADR-0002: Secret-sharing access structure as the CP-ABE substitute

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** Team (Powel, Nandini, Ojas, Avaneeth)
- **Task / source:** ARCHITECTURE.md §3, PROJECT.md §5 (backfilled)
- **Affects:** `policy`, `authority`, `records`; the paper's novelty claim and its limitations section

## Context

We need policy-based decryption across multiple independent authorities without
per-clinician pre-provisioning — the property that makes cross-institution
break-glass work. Full CP-ABE would give it, but ADR-0001 rules out the pairing
libraries it needs.

## Decision

Implement access as an AND/OR **policy tree** over Shamir secret sharing: each
leaf is an attribute whose share is encrypted to that authority's attribute key;
an AND node k-of-k-splits its parent's secret across children; an OR node gives
every child the same secret; the root secret wraps the record's DEK. A clinician
holding attribute keys that satisfy the tree reconstructs up to the root and
unwraps the DEK.

## Consequences

- Delivers multi-authority, policy-satisfaction-based decryption with no
  per-user setup — the property we actually need.
- **Not collusion-resistant.** Two clinicians could pool attribute keys to
  satisfy a policy neither satisfies alone; pairing-based CP-ABE prevents this by
  binding keys to a per-user secret, which we cannot do without pairings. This
  is an honesty requirement: it must be stated in the paper's abstract and
  limitations (PROJECT.md §5 item 4). Real CP-ABE is future work.

## Alternatives considered

- **Pairing-based CP-ABE** — the gold standard, but blocked by ADR-0001.
- **Per-clinician key pre-provisioning** — defeats the cross-institution,
  no-prior-relationship scenario that is the point of the project.
