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
| [0012](0012-shrink-proxy-reencryption.md) | Shrink proxy re-encryption to one-direction re-wrap | Accepted; wording superseded by ADR-0076 | 2026-08-18 | Team | ARCHITECTURE §5 (pre) |
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
| [0034](0034-audit-hash-chain-and-share-release.md) | Audit hash-chain field-separator encoding, full-entry signing, and savepoint-based log-before-release | Accepted; encoding superseded by ADR-0077 | 2026-09-03 | Ojas → all four | P3-3, P3-4 |
| [0035](0035-time-boxed-emergency-access-and-auto-expiry.md) | Time-boxed emergency access with forced auto-expiry: simulated-timer dual signed transitions, forced key rotation, Phase-4 audit-callback seam | Accepted | 2026-09-03 | Powel → all four | P3-6 |
| [0036](0036-revocation-by-key-rotation.md) | Revocation is full DEK re-generation + record re-encryption + policy re-compilation with generation++ + signed GRANTED→REVOKED event; not a status flag | Accepted | 2026-09-03 | Powel → all four | P3-7 |
| [0037](0037-revocation-authorization.md) | Revocation authorization check: only patient owner or home authority may revoke access; fails closed on unauthorized actor | Accepted | 2026-09-03 | Avaneeth → all four | P3-12 |
| [0038](0038-denial-and-federation-audit-events.md) | Denial/federation audit events as fixed-shape `audit.events` helpers (not call-site edits into other owners' modules); patient_id hashed in discovery events | Accepted; §3 superseded by ADR-0085 | 2026-09-06 | Ojas → all four | P3-13 |
| [0039](0039-audit-authority-services-and-deployment.md) | Audit + authority services as standalone, ephemeral FastAPI processes; break-glass share release made a real HTTP call; ADR-0034's `seq`-race gap closed with a process lock; ADR-0035's lifecycle audit-callback seam closed via HTTP client; shared-entrypoint deployment for both Path A (local) and Path B (Compose) | Accepted | 2026-09-09 | Ojas → all four | P4-2, P4-3 |
| [0040](0040-end-to-end-orchestration-and-audit-wiring.md) | Cross-hospital break-glass end-to-end orchestration and audit wiring; automatic emergency wrapping in ingest; expiry registration in breakglass unlock | Accepted | 2026-09-09 | Avaneeth → all four | P4-4 |
| [0041](0041-demo-driver-and-synthetic-dataset.md) | Demo driver and synthetic clinical dataset: one-command 8-Act examiner runner, realistic cardiac/diabetes/trauma profiles, dead-token and hash-chain verification | Accepted | 2026-09-10 | Nandini → all four | P4-5 |
| [0042](0042-traffic-capture-harness.md) | Traffic-capture harness + TLS capture profile: loopback-only dumpcap capture producing plain/tls pcaps, TLS certs via `crypto_core`, double-gated verify escape hatch; analysis stays P5-5 | Accepted | 2026-09-10 | Nandini → all four | P4-6 |
| [0043](0043-key-custodian-and-portal-integration.md) | Key Custodian service (sixth process) as every subject's key agent; portals sign/read/break-glass through it and never hold keys; consent ledger mirror, break-glass cases and patient notifications in the portal DB with `patient.lookup` / `patient.notification` / `consent.decision` chain events; `pre.delivery` decode | Accepted | 2026-09-13 | Ojas → all four | P4-7/8/8a/9/10 |
| [0044](0044-breakglass-patient-binding-and-expiry-state.md) | Break-glass endpoint enforces the assertion's patient binding (403 + denial logged, no side effect); store reconciles `emergency_open` to `granted` when the timer holds no session | Proposed; reset half superseded by ADR-0050 | 2026-10-02 | Powel (proposal) → Avaneeth / lifecycle owner | e2e run, ADR-0043 gap |
| [0045](0045-p5-5-wire-claim-checks.md) | P5-5 wire-claim checks: scenario canary manifest searched in every encoding over reassembled TCP; claim-1 scope switch (`all` default, fails today per F18; `tls` = D6-b); claim 2 proven by the Postgres COMMIT preceding the release response; claim-4 metadata pick validated on plain | Proposed; claim-1 default set by ADR-0073 | 2026-10-07 | Powel (P5-5 handover from Nandini to confirm) → all four | P5-5, F18, D6 |
| [0046](0046-p5-1-claim-registry-and-strict-xfail.md) | P5-1 evidence rules: `claim(id, level)` marker + registry meta-test; only system-level tests decide a claim; known-false claims kept at full strength as `xfail(strict=True)` citing a review finding; mutation check per control; CI fails instead of skipping without Postgres | Proposed | 2026-10-07 | Powel (P5-1 is Ojas's) → Ojas review → all four | P5-1, F34, F42 |
| [0047](0047-local-deployment-state-and-tls.md) | Shared encrypted policy and signed consent storage; verified bootstrap completion; loopback Compose portal and verified TLS | Proposed | 2026-10-09 | Avaneeth → Ojas (deploy, wire) → all four | deployment review |
| [0048](0048-breakglass-trust-anchors-from-config.md) | Break-glass trust anchors (root, facility CAs, revoked serials) come from facility configuration, never the request; Compose `pki` job generates the PKI before facilities start; chain errors are 403 + denial | Proposed | 2026-10-11 | Avaneeth → Powel, Ojas → all four | F1 |
| [0049](0049-emergency-lifetime-limits.md) | Emergency assertion lifetime and requested window capped at 3 days; facility's configured time-box is a maximum the caller can only shorten | Proposed (assertion cap superseded by 0056) | 2026-10-11 | Avaneeth → Powel, Ojas → all four | F6 |
| [0050](0050-lifecycle-state-compare-and-set.md) | Every lifecycle state change is a compare-and-set (break-glass claim/undo, revoke, insert-only ingest); ADR-0044 reset removed; expiry manager mirrors into the store and retries failed expiries | Proposed | 2026-10-11 | Avaneeth → Powel → all four | N1, N2, F7, F12, F20 |
| [0051](0051-review-fix-batch-across-owners.md) | Land the no-decision review fixes as one batch on `full-deploy` across module owners; each owner reviews their directories before merge | Proposed | 2026-10-11 | Avaneeth → module owners → all four | review fix list, CONVENTIONS §3 |
| [0052](0052-interim-authoring-allowlist.md) | Interim address allowlist on `/attribute-keys/author` (loopback; Compose names custodian and bootstrap) until signed service requests | Superseded by ADR-0066 | 2026-10-11 | Avaneeth → Ojas → all four | F14 interim |
| [0053](0053-portal-identity-hardening.md) | Portal identity bound at issuance (sign-up records a request only; unissued logins reach no portal); break-glass only for the logged lookup's patient; `portal_app` role without store access; portal hygiene | Proposed | 2026-10-11 | Avaneeth → Nandini, Ojas → all four | F17, F36, F41, F42 |
| [0054](0054-evidence-from-runs-and-analyser-false-passes.md) | Claim status from test runs (passed only); mutation check counts only real failures; analyser refuses stale/empty/gapped/incomplete captures and covers revocation | Proposed | 2026-10-11 | Avaneeth → Powel → all four | N3–N9, N15 |
| [0055](0055-portal-call-point-design-system.md) | Portal redesign: "Call Point" design system (red only for break-glass; state plates; reason/justification required; h1/h2, skip link, timer a11y; self-hosted Barlow) | Proposed | 2026-10-13 | Avaneeth → Nandini, Ojas | Impeccable critique (20/40), ADR-0014/0043 |
| [0056](0056-assertion-minutes-session-hours.md) | Emergency assertion capped at 15 minutes (replaces ADR-0049's 3 days); facility session default 4 h everywhere; timer demos set 60–120 s explicitly; portal assertion TTL is one setting | Proposed | 2026-10-13 | Avaneeth → Powel, Ojas → all four | Clinical review, ADR-0049 |
| [0057](0057-join-open-emergency-session.md) | A second break-glass on an open record joins the live session (same threshold, log-before-release, no transition, no extension) instead of 409; portal "View record again" | Proposed | 2026-10-13 | Avaneeth → Powel, Nandini → all four | Clinical review |
| [0058](0058-expiry-restores-pre-emergency-state.md) | Expiry returns a record to its pre-emergency state; `EXPIRED -> REVOKED` added so an emergency cannot undo a revocation | Proposed | 2026-10-13 | Avaneeth → Powel → all four | Clinical review, ADR-0030/0035 |
| [0059](0059-demo-patient-carries-id.md) | Demo patient carries an ID card; unidentified patients are a stated limitation (PROJECT.md §5 item 7) | Proposed | 2026-10-13 | Avaneeth → all four | Clinical review, ADR-0033 |
| [0060](0060-clinical-workflow-remediation.md) | Clinical workflow for the demo: record provenance and sensitivity metadata, care-episode consent, justification digest in the release audit entry, sensitive-record necessity, temporary encounters, guardians/next of kin, downtime capture, 4-hour default window | Proposed (contract changes need team review) | 2026-10-13 | Avaneeth → all four | Clinical review |
| [0061](0061-multi-record-declaration-and-open-record-search.md) | One declaration covers several records (each still its own assertion, threshold, audit entry); cross-record search covers only records already open, at any facility, with portal-side spelling/synonym expansion; break-glass routed to the record's facility; guardians/parents decide consent for minors | Proposed | 2026-10-14 | Avaneeth → Nandini, Powel → all four | Clinical review, ADR-0057/0060 |
| [0062](0062-record-shown-whenever-open-case-is-viewed.md) | An open case shows its record on every page view through the ADR-0057 join (audited, threshold, no extension); "View record again" button removed; nothing stored | Proposed | 2026-10-14 | Avaneeth → Nandini → all four | Clinician usability, ADR-0057 |
| [0063](0063-join-limited-to-opener-facility.md) | Only clinicians of the opener's facility (from the verified issuing CA) may join an open emergency session; others get an audited 403 before the threshold gate | Proposed | 2026-10-14 | Avaneeth → Powel → all four | ADR-0057/0061 follow-up |
| [0064](0064-patient-certificates-and-signed-labels.md) | Patients get certificates from their home facility CA (OU `patient`); the patient signs each record's clinical labels; unsigned or unverifiable labels get the strictest rules; consent is verified against a certified patient key, never a caller-supplied one | Proposed | 2026-10-14 | Powel → Avaneeth, Ojas, Nandini → all four | PR #40 review findings 1, 3, 14 |
| [0065](0065-one-time-declare-token.md) | The break-glass form carries a one-time declare token (a reloaded or re-sent declaration is a 409 and opens nothing); the case page refreshes to its own URL by GET; viewing a case only joins (`join_only`) | Proposed | 2026-10-15 | Powel → Nandini | Re-declare loop on `main` after PR #40 |
| [0066](0066-signed-service-requests.md) | Every service-to-service call is a signed one-time `RequestEnvelope` (in headers; body unchanged) from a root-certified service identity (OU `service:<kind>`), checked before any route runs, with per-route kind permissions; reads refuse a keyless requester before touching storage; the portal gets a service key (not a subject key); replaces the F14 address allowlist | Proposed | 2026-10-15 | Powel → Ojas, Avaneeth, Nandini → all four | Review D5-a / F34 / F14 (C9); reverses part of ADR-0015 |
| [0067](0067-audit-validates-assertion.md) | The audit service validates the clinician's emergency assertion itself (chain, five-point check, record-bound digest, its own replay set) before it commits or releases share 3; the entry records the validated fields | Proposed | 2026-10-15 | Powel → Ojas | Review D1-a / F2 (C3); supersedes part of ADR-0044 |
| [0068](0068-clinician-signed-breakglass-transition.md) | The custodian signs the `-> EMERGENCY_OPEN` transition with the clinician's own key; the facility and gate verify it against the clinician certificate before any share is combined; no private key in the unlock request | Proposed | 2026-10-15 | Powel → Ojas, Avaneeth | Review D8-a / F11 (C7) |
| [0069](0069-full-rotation-at-expiry.md) | Expiry runs a full rotation: new DEK, policy root, emergency key and shares (handed to custodian and audit by generation), search index re-derived from a term list sealed under the DEK; stored atomically, retried to completion | Proposed | 2026-10-15 | Powel → Avaneeth, Nandini, Ojas → all four | Review D3-a / F9 (C4) |
| [0070](0070-p53-search-workload-and-observer-views.md) | P5-3 measures search leakage from an opt-in `--search-workload` (repeats, hits/misses, an expiry, a second break-glass via the custodian) and reads three observer views: HTTP, the plaintext Postgres link (tokens, row counts) and TLS record sizes; reports carry token fingerprints only | Proposed | 2026-10-15 | Powel → Nandini, Avaneeth | WORKFLOW.md P5-3; PROJECT.md §4A claim 3 |
| [0071](0071-tls-on-the-store-link.md) | The TLS profile covers the facility-store link: every client uses `sslmode=verify-full` against its own `store.crt` (set once in `configure_transport`; a weaker DSN is refused), the store serves TLS 1.3 only with `hostnossl … reject`; the plain profile is unchanged; P5-3 labels TLS exchanges from the workload's search manifest | Proposed | 2026-10-15 | Powel → Avaneeth, Nandini | ADR-0070 finding; WORKFLOW.md P5-3 |
| [0072](0072-no-private-key-or-dek-in-facility-requests.md) | No facility request takes a private key or a DEK: the custodian signs the patient's `GRANTED -> REVOKED` event; the facility verifies it against the patient certificate, requires it fresh and one-time, and unwraps the current DEK through the policy; the key-taking consent routes are removed; home-authority revocation over HTTP refused until it has a certified identity | Proposed | 2026-10-15 | Avaneeth → Ojas → all four | Review D6 step 1, F10 |
| [0073](0073-claim-1-scoped-to-tls.md) | §4A claim 1 ("no plaintext on the wire") holds under the TLS profile; analyser `--claim1-scope` defaults to `tls`; the plain capture is the positive control; client-side crypto (D6-a) is future work | Proposed; shares sealed by ADR-0079 | 2026-10-15 | Avaneeth → Powel → all four | Review D6-b; ADR-0045 |
| [0074](0074-breakglass-two-of-two-share-2-reserved.md) | Break-glass is 2-of-2 in this build: the 2-of-3 split's home-authority share is reserved, not deposited, so every reconstruction needs the audit service; docs and threat model corrected | Proposed | 2026-10-15 | Avaneeth → Powel, Ojas → all four | Review D2-b, F3 |
| [0075](0075-credential-revocation-does-not-revoke-released-keys.md) | Credential revocation stops future key release only; a released attribute key stays valid, including across record rotation; stated as a limitation | Proposed | 2026-10-15 | Avaneeth → Ojas → all four | Review D10-a, F44 |
| [0076](0076-pre-is-bidirectional.md) | The ElGamal PRE is bidirectional and break-glass delivers an unwrapped DEK by KEM; docs and docstrings corrected, construction unchanged; supersedes ADR-0012's unidirectional wording | Proposed | 2026-10-15 | Avaneeth → Ojas, Powel → all four | Review D11-a, F32 |
| [0077](0077-domain-tagged-length-prefixed-encoding.md) | Signed, hashed and AAD bytes use `crypto_core.encode_fields` (domain tag + 4-byte length prefixes) in every module; DEK-wrapping AAD binds record, policy and generation; supersedes ADR-0034's `0x1f` encoding | Proposed | 2026-10-15 | Avaneeth → Powel, Ojas → all four | Review D9-a, F23, F29 |
| [0078](0078-dev-tls-certs-keep-localhost-sans.md) | Demo TLS certificates keep the `localhost` / `127.0.0.1` SANs that host-run paths need; residual impersonation risk recorded | Proposed | 2026-10-15 | Avaneeth → Ojas → all four | Review N14 |
| [0079](0079-shares-travel-sealed.md) | Threshold shares travel sealed to their recipient: each holder and facility publishes an ElGamal share key signed by its root-certified service identity (`GET /share-key`); deposits, rotation re-deposits, release and unlock carry only sealed shares (KEM + AES-GCM, AAD binds record, index, recipient); audit seals share 3 straight to the facility gate; analyser fails claim 1 on any plain share and times the sealed share 3 for claim 2 | Proposed | 2026-10-15 | Avaneeth → Powel, Ojas → all four | Review D6 step 2; ADR-0073 |
| [0080](0080-revocation-without-keys-on-the-wire.md) | Revocation is a patient-signed GRANTED -> REVOKED verified against the patient certificate; the facility recovers the DEK through the policy and re-keys with the ADR-0069 rotation (works on Postgres, re-keys break-glass); consent requests arrive signed, grant revocation is a signed REVOKED grant; no private key or DEK in any body | Proposed | 2026-10-15 | Powel → Avaneeth (api, records, identity, storage), Ojas (custodian, audit) → all four | review F10, F13, D4 |
| [0081](0081-restart-and-crash-recovery.md) | Open emergency sessions are stored as keyless rows; a restarted facility closes its own with a rotation recovered through the policy (restart mid-window, crash mid-rotation); share holders accept any later generation | Proposed | 2026-10-15 | Powel → Avaneeth (api, storage) | review F5; ADR-0069 residual |
| [0082](0082-key-release-proof-of-possession.md) | An attribute key is released only against a one-time envelope its credential's subject signed, under a certificate from a configured facility CA; authorities get FACILITY_CA_CERTS_DIR | Proposed | 2026-10-15 | Powel → Ojas (authority, custodian, deploy), Avaneeth (identity) | review F15 |
| [0083](0083-audit-high-water-mark-on-facility-disk.md) | A facility keeps the highest audit seq it has seen in a file on its own disk (`AUDIT_HIGH_WATER_FILE`, required), so a restart still refuses a truncated chain; not in the shared store, which every service reaches as the same role | Proposed | 2026-10-19 | Ojas → Avaneeth (api, deploy) | review F31 remainder |
| [0084](0084-revocation-is-patient-only-in-this-build.md) | Only the patient revokes in this build; ARCHITECTURE §5 and PROJECT §5 item 1 now say home-authority revocation is future work | Proposed | 2026-10-19 | Ojas → all four | review F10 remainder; ADR-0080 |
| [0085](0085-no-name-or-dob-in-the-chain-patient-id-is-the-pseudonym.md) | The `patient.lookup` event drops `query_hash` (an unsalted, reversible hash of name and date of birth); `federation.discovery` logs `patient_id` like every other event instead of a reversible hash of it; the chain is stated as pseudonymous (no portal PII, patients named by `patient_id`); the hashed-id test is replaced by a no-PII-in-`audit_log` negative test | Proposed | 2026-10-19 | Ojas → Nandini (portal/clinician), portal_core owner, Avaneeth (api), Powel (tests/security) → all four | whole-project check 2026-10-19; amends ADR-0038 §3 |

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
