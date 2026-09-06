# ADR-0016: Patient self-access via an owner attribute, not a dual-wrapped DEK

- **Status:** Accepted (ratified 2026-09-06, Phase 3 close housekeeping)
- **Date:** 2026-08-21
- **Deciders:** Powel → all four (patient-key custody touches `authority` and `ui`)
- **Task / source:** P4-7 (patient portal), ARCHITECTURE §3 / §5; PROJECT §5A, ADR-0014
- **Affects:** `policy` (C7), `authority` (C6), `records` (C8 ingest), `ui` patient portal (P4-7); relates to ADR-0014

## Context

Records are uploaded and encrypted by the hospital (facility node): a fresh DEK
per record, the DEK wrapped to the root secret of an access-policy tree
(ARCHITECTURE §3). Clinician reads reconstruct the root secret up that tree and
unwrap the DEK (ARCHITECTURE §5, normal read).

Nothing in the design says how a **patient reads their own record**. The patient
portal (P4-7) currently only lets a patient approve/deny/revoke grants and view
access history — it has no decrypt-and-view path, and per ADR-0014 the portal
*identifies* the patient but must never *decide* access or hold keys. So for a
patient to see their own uploaded PDF, they must be a party that can satisfy the
record's policy, and the mechanism for that was unspecified.

Two options were on the table:

1. **Patient-as-attribute** — every record's policy tree carries a root-level
   `OR` with an `owner:<patient_id>` leaf; the patient holds an attribute key for
   that leaf. Self-access is the *same* reconstruction path as any clinician read.
2. **Dual-wrap at ingest** — wrap the DEK a second time directly to the patient's
   own key, as an extra `DEKWrapping` alongside the policy-root wrapping.

## Decision

Adopt **patient-as-attribute** (option 1).

- Every record's policy tree gains a root-level `OR` whose branches are the
  clinical policy (as today) and a single leaf `owner:<patient_id>`.
- The patient's `owner:<patient_id>` attribute key is issued and held by the
  patient's **home authority** — the party that already issues attribute keys
  and holds break-glass Share 2 (ARCHITECTURE §5). It is **not** held by the
  Django portal or Postgres.
- Patient view flow: portal login identifies the patient → backend runs the
  normal read path (ARCHITECTURE §5) → the policy engine reconstructs the root
  secret via the owner attribute served by the home authority → the DEK unwraps
  → the PDF is AES-256-GCM decrypted and **streamed to the browser for that
  request only**. Plaintext is never persisted server-side and never logged
  (CONVENTIONS §2 rule 3).

This keeps **one decryption mechanism** — satisfy the policy tree, reconstruct,
unwrap — which is the project's central unification claim (PROJECT §1).

## Consequences

- **Single path preserved.** Patient and clinician reads use the same policy
  reconstruction; there is no second, parallel way to obtain a DEK to explain or
  defend in the viva.
- **Rotation is automatic.** Revocation/expiry re-wrap the tree root
  (ARCHITECTURE §5); the owner leaf rides along with no extra bookkeeping. The
  dual-wrap option would have required re-wrapping a separate patient envelope on
  every rotation — an easy fail-*open* bug if forgotten.
- **ADR-0014 boundary holds.** Login says who is asking; the home authority's
  release of the owner attribute (not the portal) is what enables the unwrap.
- **Scope grows for P4-7.** A decrypt-and-render (stream) view is added to the
  patient portal; the matching `WORKFLOW.md` line records it so it is not
  smuggled in past the task's "Done when."
- **Sequencing — this is not only a Phase 4 change.** Although the *view* is
  P4-7, the owner-leaf convention must be honored where policies are authored
  and records are ingested: attribute issuance (P2-2), policy-engine authoring
  (P2-3), and the record upload path (P3-14). If records are ingested in Phase
  2–3 without the `owner` leaf, the Phase 4 view has nothing to reconstruct
  against. The convention is therefore baked in from ingest, not retrofitted —
  those three tasks carry matching notes. **No frozen-contract change is
  required:** `owner:<patient_id>` is an `Attribute(name, value)` on an existing
  `PolicyTree` leaf, so no all-four `contract:` PR is triggered.
- **Honest downside — the owner leaf is a standing single-key entry.** It sits
  under `OR`, so one key suffices; anyone holding the patient's owner-attribute
  key reads every record of that patient. That is correct for self-access (a
  patient legitimately reads alone), but it makes home-authority custody of that
  key a real trust dependency, and it does not improve the documented
  collusion limitation (PROJECT §5, item 4) — it just does not worsen it.
- **New negative test.** A test must assert the patient portal never uses portal
  login state alone to release a DEK — decryption must fail if the owner
  attribute is absent, even for a logged-in patient (fail closed).
- **Widens the rogue-authority blast radius (threat-model §5).** Because the home
  authority now issues and holds the patient's `owner:<patient_id>` key, a rogue
  home authority can mint that key and read *all* of that patient's records. It
  adds no new trusted party — the home authority already holds break-glass
  Share 2 — but it widens what a rogue one can do. Recorded as a residual risk in
  `docs/threat-model.md` §5 and to be carried into the paper's limitations
  alongside `PROJECT.md` §5 item 3.

## Alternatives considered

- **Dual-wrap the DEK to the patient's key at ingest.** Rejected: it introduces
  a second DEK-access path that bypasses the policy tree, fragmenting the "one
  mechanism" story the project exists to make, and it adds rotation bookkeeping
  whose failure mode is fail-open.
- **Let the portal hold the patient's key and decrypt in Django.** Rejected
  outright: it makes portal login the thing that releases a key, which destroys
  the ADR-0014 boundary and the project's novelty.
