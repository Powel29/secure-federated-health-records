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
| [0006](0006-lint-format-ruleset.md) | Lint/format ruleset enforcing crypto rules in CI | Accepted | 2026-08-12 | Powel → Nandini | T01 / T05 |
| [0007](0007-pydantic-v2-contracts.md) | Pydantic v2 for the contract schemas | Accepted | 2026-08-12 | Powel → all four | T02 |
| [0008](0008-contract-set-nine-schemas.md) | Freeze the contract set at nine schemas, not seven | Accepted | 2026-08-12 | Powel → all four | T02 |
| [0009](0009-transitionevent-no-expiry-ts.md) | TransitionEvent carries no expiry_ts in v1 | Accepted | 2026-08-12 | Powel → all four | T02 |
| [0010](0010-crypto-federation-over-fhir.md) | Default to cryptographic-federation model over FHIR | Accepted | 2026-08-13 | Team (faculty-confirmed) | T03 |
| [0011](0011-single-shared-store.md) | Single shared encrypted store, not per-facility storage | Accepted | 2026-08-18 | Team | ARCHITECTURE §5 |
| [0012](0012-shrink-proxy-reencryption.md) | Shrink proxy re-encryption to one-direction re-wrap | Accepted | 2026-08-18 | Team | ARCHITECTURE §5 (pre) |
| [0013](0013-dashboard-early-shell.md) | Dashboard built as an early shell that grows per phase | Superseded by ADR-0014 | 2026-08-18 | Team | ARCHITECTURE §2 C16 |
| [0014](0014-web-portals-and-postgres.md) | Three web portals replace the dashboard; PostgreSQL as storage | Accepted | 2026-08-18 | Team | PROJECT §5A |
| [0015](0015-strictness-pass-cuts.md) | Strictness-pass cuts (service-signing, plain-HTTP guard, BOLA middleware) | Accepted | 2026-08-18 | Team | PROJECT §4B |
| [0016](0016-patient-self-access-as-attribute.md) | Patient self-access via an owner attribute, not a dual-wrapped DEK | Accepted | 2026-08-21 | Powel → all four | P4-7 |
| [0017](0017-contract-additions-consent-correlation.md) | Contract additions for consent + correlation; RequestEnvelope reconciliation | Accepted | 2026-08-21 | Powel → all four | ADR-0014/0015/0016 |
| [0018](0018-crypto-spike-findings.md) | Crypto sanity-spike findings | Accepted | 2026-08-21 | Avaneeth → all four | P0-6 |
| [0019](0019-federation-topology-and-attributes.md) | Federation at two facilities; attribute-authority ownership | Accepted | 2026-08-21 | Powel (team) | P0-7 |
| [0020](0020-psycopg3-raw-sql-storage.md) | psycopg3 + raw SQL migrations for the store (no ORM) | Accepted | 2026-08-21 | Avaneeth (team) | P0-8 |
| [0021](0021-early-portal-shells-and-registration.md) | Early portal shells + self-service registration (request-then-issue) | Accepted | 2026-08-21 | Team | portal shells |
| [0022](0022-aes-gcm-no-caller-nonce.md) | Remove caller-supplied nonce from `aes_gcm_encrypt` | Accepted | 2026-08-25 | Phase-1 review → Powel | P1-1 review |
| [0023](0023-pre-subgroup-validation.md) | Validate order-q subgroup membership in the ElGamal PRE | Accepted | 2026-08-25 | Phase-1 review → Ojas | P1-5 review |
| [0024](0024-single-root-cross-certification.md) | Cross-certification via a single shared root, not a peer CA mesh | Accepted | 2026-08-30 | Avaneeth | P2-1, P2-2 |
| [0025](0025-p2-1-p2-2-ownership-swap.md) | Swap ownership of P2-1/P2-2 from Avaneeth to Ojas | Accepted | 2026-08-30 | Ojas, Avaneeth | P2-1, P2-2 |
| [0026](0026-policy-engine-cryptographic-enforcement.md) | Policy engine enforces access cryptographically (Shamir over attribute keys), not by boolean check alone | Accepted | 2026-08-30 | Powel | P2-3 |
| [0027](0027-search-token-construction.md) | Search-token construction: deterministic HKDF over emergency key with versioned salt; per-record binding and normalisation deferred | Accepted | 2026-08-30 | Nandini, Powel → all four | P2-5 |
| [0028](0028-credential-lifecycle-and-revocation-registry.md) | Credential lifecycle and revocation registry | Accepted | 2026-08-30 | Avaneeth (team) | P2-6 |
| [0029](0029-simplify-revocation-registry.md) | Simplify revocation registry to serial-keyed O(1) lookup | Accepted | 2026-08-30 | Avaneeth (team) | P2-6 review |
| [0030](0030-lifecycle-state-machine.md) | Lifecycle state machine: six-transition legal set, signature-before-legality on verify, in-memory consumed-id store consumed after signature check | Accepted | 2026-08-31 | Powel → all four | P3-1 |
| [0031](0031-consent-as-gate.md) | Patient consent is a read-time gate over an already-wrapped record, not a wrap-time re-policy; revocation is a fresh patient-signed grant with `status=REVOKED` | Accepted | 2026-08-31 | Powel → all four | P3-2 |
| [0032](0032-emergency-assertion-and-anti-replay.md) | Emergency assertion five-point validation and thread-safe anti-replay consumed-ID stores | Accepted | 2026-08-31 | Avaneeth → all four | P3-10, P3-11 |
| [0033](0033-emergency-patient-identification.md) | Emergency patient identification is a name + DOB search in the clinician portal (PII stays in portal DB, never in the crypto store); slot as P4-8a | Accepted | 2026-09-02 | Team (Powel, Nandini, Ojas, Avaneeth) | Gap against §8 / P3-10 |
| [0034](0034-audit-hash-chain-and-share-release.md) | Audit hash-chain field-separator encoding, full-entry signing, and savepoint-based log-before-release | Accepted | 2026-09-03 | Ojas → all four | P3-3, P3-4 |
| [0035](0035-time-boxed-emergency-access-and-auto-expiry.md) | Time-boxed emergency access with forced auto-expiry: simulated-timer dual signed transitions, forced key rotation, Phase-4 audit-callback seam | Accepted | 2026-09-03 | Powel → all four | P3-6 |
| [0036](0036-revocation-by-key-rotation.md) | Revocation is full DEK re-generation + record re-encryption + policy re-compilation with generation++ + signed GRANTED→REVOKED event; not a status flag | Accepted | 2026-09-03 | Powel → all four | P3-7 |
| [0037](0037-revocation-authorization.md) | Revocation authorization check: only patient owner or home authority may revoke access; fails closed on unauthorized actor | Accepted | 2026-09-03 | Avaneeth → all four | P3-12 |
| [0038](0038-denial-and-federation-audit-events.md) | Denial/federation audit events as fixed-shape `audit.events` helpers (not call-site edits into other owners' modules); patient_id hashed in discovery events | Accepted | 2026-09-06 | Ojas → all four | P3-13 |
| [0039](0039-audit-authority-services-and-deployment.md) | Audit + authority services as standalone, ephemeral FastAPI processes; break-glass share release made a real HTTP call; ADR-0034's `seq`-race gap closed with a process lock; ADR-0035's lifecycle audit-callback seam closed via HTTP client; shared-entrypoint deployment for both Path A (local) and Path B (Compose) | Accepted | 2026-09-09 | Ojas → all four | P4-2, P4-3 |
| [0040](0040-end-to-end-orchestration-and-audit-wiring.md) | Cross-hospital break-glass end-to-end orchestration and audit wiring; automatic emergency wrapping in ingest; expiry registration in breakglass unlock | Accepted | 2026-09-09 | Avaneeth → all four | P4-4 |
| [0041](0041-demo-driver-and-synthetic-dataset.md) | Demo driver and synthetic clinical dataset: one-command 8-Act examiner runner, realistic cardiac/diabetes/trauma profiles, dead-token and hash-chain verification | Accepted | 2026-09-10 | Nandini → all four | P4-5 |
| [0042](0042-traffic-capture-harness.md) | Traffic-capture harness + TLS capture profile: loopback-only dumpcap capture producing plain/tls pcaps, TLS certs via `crypto_core`, double-gated verify escape hatch; analysis stays P5-5 | Accepted | 2026-09-10 | Nandini → all four | P4-6 |
| [0043](0043-key-custodian-and-portal-integration.md) | Key Custodian service (sixth process) as every subject's key agent; portals sign/read/break-glass through it and never hold keys; consent ledger mirror, break-glass cases and patient notifications in the portal DB with `patient.lookup` / `patient.notification` / `consent.decision` chain events; `pre.delivery` decode | Accepted | 2026-09-13 | Ojas → all four | P4-7/8/8a/9/10 |

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
