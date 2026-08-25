# Decision log (ADRs)

This is the project's **running decision log**. Every choice with alternatives —
by anyone on the team — is recorded here as an Architecture Decision Record so
that six months later we know *what* was decided, *why*, *who* decided it, and
*what it touched*. The channel message where a decision was actually made is not
the record; the ADR is. CONVENTIONS.md §6 makes this mandatory.

The table below is the tracker — scan it to see every decision at a glance.
Each row links to a one-file ADR with the full context.

## Index

| ADR | Title | Status | Date | Deciders | Task / source |
|---|---|---|---|---|---|
| [0001](0001-reject-charm-crypto.md) | Reject Charm-Crypto; hand-roll primitives | Accepted | 2026-08-12 | Team | ARCHITECTURE §1 |
| [0002](0002-secret-sharing-access-structure.md) | Secret-sharing access structure as CP-ABE substitute | Accepted | 2026-08-12 | Team | ARCHITECTURE §3 |
| [0003](0003-simulated-hsm-timer.md) | Simulate the HSM/KMS emergency timer | Accepted | 2026-08-12 | Team | ARCHITECTURE §7, PROJECT §5 |
| [0004](0004-src-layout-imports.md) | Python src-layout, bare-name imports, editable install | Accepted | 2026-08-12 | Powel | T01 |
| [0005](0005-pinned-deps-single-source.md) | Pin runtime deps once in requirements.txt | Accepted | 2026-08-12 | Powel | T01 |
| [0006](0006-lint-format-ruleset.md) | Lint/format ruleset enforcing crypto rules in CI | Proposed | 2026-08-12 | Powel → Nandini | T01 / T05 |
| [0007](0007-pydantic-v2-contracts.md) | Pydantic v2 for the contract schemas | Proposed | 2026-08-12 | Powel → all four | T02 |
| [0008](0008-contract-set-nine-schemas.md) | Freeze the contract set at nine schemas, not seven | Proposed | 2026-08-12 | Powel → all four | T02 |
| [0009](0009-transitionevent-no-expiry-ts.md) | TransitionEvent carries no expiry_ts in v1 | Proposed | 2026-08-12 | Powel → all four | T02 |
| [0010](0010-crypto-federation-over-fhir.md) | Default to cryptographic-federation model over FHIR | Accepted | 2026-08-13 | Team (faculty-confirmed) | T03 |
| [0011](0011-single-shared-store.md) | Single shared encrypted store, not per-facility storage | Accepted | 2026-08-18 | Team | ARCHITECTURE §5 |
| [0012](0012-shrink-proxy-reencryption.md) | Shrink proxy re-encryption to one-direction re-wrap | Accepted | 2026-08-18 | Team | ARCHITECTURE §5 (pre) |
| [0013](0013-dashboard-early-shell.md) | Dashboard built as an early shell that grows per phase | Superseded by ADR-0014 | 2026-08-18 | Team | ARCHITECTURE §2 C16 |
| [0014](0014-web-portals-and-postgres.md) | Three web portals replace the dashboard; PostgreSQL as storage | Accepted | 2026-08-18 | Team | PROJECT §5A |
| [0015](0015-strictness-pass-cuts.md) | Strictness-pass cuts (service-signing, plain-HTTP guard, BOLA middleware) | Accepted | 2026-08-18 | Team | PROJECT §4B |
| [0016](0016-patient-self-access-as-attribute.md) | Patient self-access via an owner attribute, not a dual-wrapped DEK | Proposed | 2026-08-21 | Powel → all four | P4-10 |
| [0017](0017-contract-additions-consent-correlation.md) | Contract additions for consent + correlation; RequestEnvelope reconciliation | Proposed (`contract:`) | 2026-08-21 | Powel → all four | ADR-0014/0015/0016 |
| [0018](0018-crypto-spike-findings.md) | Crypto sanity-spike findings | Proposed | 2026-08-21 | Avaneeth → all four | P0-6 |
| [0019](0019-federation-topology-and-attributes.md) | Federation at two facilities; attribute-authority ownership | Accepted | 2026-08-21 | Powel (team) | P0-7 |
| [0020](0020-psycopg3-raw-sql-storage.md) | psycopg3 + raw SQL migrations for the store (no ORM) | Accepted | 2026-08-21 | Avaneeth (team) | P0-8 |
| [0021](0021-early-portal-shells-and-registration.md) | Early portal shells + self-service registration (request-then-issue) | Accepted | 2026-08-21 | Team | portal shells |
| [0022](0022-aes-gcm-no-caller-nonce.md) | Remove caller-supplied nonce from `aes_gcm_encrypt` | Proposed | 2026-08-25 | Phase-1 review → Powel | P1-1 review |
| [0023](0023-pre-subgroup-validation.md) | Validate order-q subgroup membership in the ElGamal PRE | Proposed | 2026-08-25 | Phase-1 review → Ojas | P1-5 review |

## Owed, not yet written

Decisions already made in the docs that still need their own ADR (whoever owns
the area writes it):

- ~~**Signed inter-service requests instead of mTLS** — ARCHITECTURE §8.~~
  **Resolved.** The "separate service-identity control replacing mTLS" was cut on
  the strictness pass (ADR-0015); the `RequestEnvelope` that remains is a replay/
  integrity wrapper, restated as such in ADR-0017. Service identity comes from the
  PKI and cross-certification (P2-1). No standalone ADR is owed.

## How to add one

1. Copy [`template.md`](template.md) to `NNNN-short-title.md`, using the next
   free number and a kebab-case title.
2. Fill in every section. Aim for about half a page — context, decision,
   consequences. If there was no real alternative, it is not an ADR.
3. Add a row to the index table above **in the same PR** as the ADR. An ADR that
   is not in the table is not tracked.
4. For a contract change, the ADR and the all-four `contract:` PR
   (CONVENTIONS.md §3) go together — the ADR is where the "why" lives.

## Statuses

- **Proposed** — written, not yet ratified by whoever must sign off (a reviewer,
  or all four for a contract).
- **Accepted** — ratified and in force.
- **Superseded by ADR-NNNN** — replaced by a later decision. Never edit an
  Accepted ADR's decision in place; write a new ADR and link both ways, so the
  history stays readable.
- **Deprecated** — no longer relevant, but kept for the record.

## When a decision is a decision

Write an ADR when a choice: changes or freezes a contract; changes how two
modules talk; picks a library, algorithm, or tool; touches the build, CI, or
deployment; adds, removes, or weakens a security control; or reverses/resolves
something stated in `PROJECT.md`, `ARCHITECTURE.md`, `CONVENTIONS.md`, or
`WORKFLOW.md`. Routine code that follows an existing decision does not need one.
