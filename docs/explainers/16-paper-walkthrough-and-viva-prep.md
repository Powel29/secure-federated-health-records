# 16. The paper, section by section, for viva preparation

The paper is `paper/build/main.pdf` (IEEEtran, 10 pages, built with Tectonic; sources
in `paper/sections/`, `paper/tables/`, `paper/figures/`). Title: *Federated Break-Glass
EHR with a Unified Key-Lifecycle State Machine*. Authors: Ojas Thakurela, Powel Lawrence
Lewis, Avaneeth Gowda L, Nandini Taldar (MIT, Manipal). It describes the evaluated
commit `57a1a8c`.

**Rule:** the paper is the reference. Every other explainer is a gloss on it. Each
sentence in the paper's source ends with a `% src:` tag pointing to a fact sheet in
`paper/notes/facts-*.md`, which in turn cites a file and line in the repository. If a
reviewer asks "where does this come from?", that is the chain.

## The paper in 60 seconds

Log-gated decryption exists (accountable and transparent decryption) and so does
break-glass for health records, but in the works we compare, **log-gated schemes have no
patient revocation lifecycle** and **health-record break-glass schemes are not described as
gating key release on a committed log entry**. We build a federated EHR prototype where
**revocation, break-glass and expiry are signed, logged transitions of one key-lifecycle
state machine over per-record keys**; consent is a patient-signed grant checked at read time,
separate from the state; revocation and expiry re-key in full, **opening break-glass rotates
nothing**; the audit service holds **two of four** emergency-key shares and releases them
only after validating a signed one-time Emergency Assertion and committing a hash-chained
entry; emergency search derives from that key and ends at expiry. On a simulated federation
with synthetic data **all eleven security claims hold** in a live run and PyShark checks see
the audit commit on the wire before the shares. **Limitations are in the abstract.**

## Section by section

| § | Title | What it says | Who to ask | Companion file |
|---|---|---|---|---|
| Abstract | | Combination claim; evidence; the headline limitations | all | this file |
| I | Introduction | Problem; prior art acknowledged; four contributions; two ways we are weaker | Powel | 01 |
| II | Related Work | Comparison matrix; five groups of prior work | Avaneeth/Powel | below |
| III | Threat Model and Goals | Assets; adversaries A to D; four trusted parties; goals C1 to C11 | Ojas | 04, 13, 17 |
| IV | System Overview | Simulated federation; components; trust boundaries; what portals/Postgres may not do; caveats | Ojas/Avaneeth | 01, 09 |
| V | Key-Lifecycle State Machine | States, 7 transitions, signed events, expiry, access structure | Powel | 02, 04, 12 |
| VI | Break-Glass Protocol | Assertion and replay; weighted 3-of-4 gate; commit-then-release; hash chain; expiry by rotation | Powel/Ojas/Avaneeth | 03, 05 |
| VII | Security Analysis | Claims table; per-claim arguments; mutation testing; what is proven | Ojas/Powel | 17, 07 |
| VIII | Traffic Analysis | PyShark checks; wire results; search leakage | Nandini | 06, 15 |
| IX | Implementation and Evaluation | Stack; suite results; method; benchmarks; expansion | Nandini | 09, 17 |
| X | Limitations | 13 caveats plus further limits | all | 07 |
| XI | Conclusion | Summary; future work | Powel | 01, 08 |

## Section I: the four contributions and the two weaknesses

1. **One signed, logged key lifecycle.** Revocation, break-glass and expiry rotate/transition
   over per-record DEKs; consent is separate. Revocation and expiry rotate the **DEK, the
   policy root, the emergency key with its shares, and the search index**; opening
   break-glass rotates **nothing**.
2. **Transparent-decryption-style log gating for federated break-glass.**
3. **Emergency-scoped search.**
4. **Evidence.** Eleven claims; PyShark wire checks.

**Weaker than the literature in two ways:** the log is a plain hash chain held by a trusted
audit service with **no proofs of presence or extension**, and there is **no formal model**.

## Section II: related work, group by group

The paper's comparison table uses columns **CE** (keys decide access, not a policy check), **LG**
(key release gated on a log entry), **BG** (break-glass), **LC** (consent and revocation in one
lifecycle), **TB** (time-boxed expiry), **ES** (emergency-scoped search), **FP** (formal proof
or model), **IMP** (implemented). **Our row:** CE yes, LG yes (trusted hash chain), BG yes,
LC partial (revocation is a lifecycle transition, consent is outside), TB yes (server-enforced),
ES yes, **FP no**, IMP yes.

| Group | Works | What they do | What differs from us |
|---|---|---|---|
| Accountable / transparent decryption | Ryan 2017; Cheval, Moreira & Ryan 2023; Kroll et al.; Larch (Dauterman 2023); Li et al. 2025 | Key (or a share) used only once the request is in a log. Ryan: trusted hardware + log with proofs of presence/extension. Cheval: ProVerif-verified, Merkle-tree log proofs. Kroll: approver + threshold of decryption authorities + auditor-certified public log, names **hospital emergencies** as an application | Stronger log than ours. We instantiate the primitive and add a revocation/expiry lifecycle |
| Break-glass access control | Ferreira 2006; Brucker & Petritsch 2009; Marinovic (Rumpole) 2011 | Break-the-glass policy in the access-control model | Policy checks in software. In ours, keys and the threshold gate decide access and the log entry precedes key release |
| Cryptographic break-glass | Brucker et al. 2010; LiBAC (Yang 2018); Zhang et al. 2016; Scafuro 2019; de Oliveira 2019/2020 | ABE-based break-glass; password + accountable KGC; breakable-once encryption; task/team-scoped emergency access with signed tokens | None gates key release on a committed log entry (Scafuro's break is *detectable*, not log-gated). Our expiry **re-keys** instead of trusting a provider to block access. Several have formal analyses we lack |
| Encrypted PHR sharing | Li et al. 2013 | Patient-centric multi-authority ABE, on-demand revocation, break-glass | We keep the setting but release the emergency key only through an audit-logged threshold, and the emergency ends with a rotation |
| Time-limited search | Yang & Ma 2016 | Patient delegates keyword search/decryption for a period | Prior art. We only derive emergency search tokens from the emergency key (an engineering choice) |
| Consent at the policy layer | Muslim & Grégoire 2026; Romel et al. 2025 | XACML consent lifecycle (logical, not cryptographic); blockchain permissions, two-physician co-signed 2-hour emergency request | Their enforcement is logical/on-chain; **Romel's emergency grant is logged but key release goes through a separate, design-only HSM guardian, not gated on the log** |

## Section III: the threat model in one page

- **Assets (priority order):** PHI plaintext, per-record DEKs, each record's emergency key,
  attribute keys, audit-chain integrity, metadata (**not** hidden).
- **Adversaries (modelled separately):** (A) shared store, honest-but-curious or dumped;
  (B) compromised facility; (C) rogue attribute authority; (D) colluding clinicians (**not
  stopped**). **No on-path network attacker.**
- **Trusted, not modelled as adversaries:** the audit service, the Key Custodian, the
  emergency timer (simulated HSM), the PKI root.
- **Trust assumptions:** AES-256-GCM, ECDSA, SHA-256, HKDF and Shamir are assumed sound.
- **Out of scope:** rate limiting, MFA, session threats.
- **Goals:** C1 to C11 (file 17 has the exact wording).

## Section IV: what to be able to draw (paper Fig. 1)

Rows: Browser, Portals (Django, **no subject keys**), Postgres store (ciphertext, wrapped
keys, index, log); Authority net (**share x=2**), Key Custodian (**all persona keys, share
x=1**, trusted), Audit service (**hash chain, shares x=3,4**, trusted); Authority med,
Facility A, Facility B (**threshold gates, hold no records**). Thick arrows carry
emergency-key shares, sealed to a facility's gate; share 2 is used only if share 1 is missing.

## Section V to VI: the five things to be able to recite

1. The four states and **seven** legal arrows (file 2).
2. The signed-event apply order: **signature, legality, from-state, consume** (file 2).
3. The rotation list: **DEK, policy root, emergency key + shares, search index** (file 2).
4. The assertion validation order, **consumption last**, three validators (file 3).
5. Commit-then-release, **COMMIT 1.35 ms before the response** (files 3 and 6).

## Section VII: what is proven (the honest table)

Library primitives (AES-GCM, HKDF, ECDSA) are **assumed**, not proven by us. The **hash chain,
Shamir code, policy tree, PRE, KEM and deterministic search tokens are not proven.** Shamir's
scheme is assumed; our code is not proven. This is the security-properties table of the paper.
Be ready to say, for each row, *tested by* (which claim) versus *proven* (nothing, apart from
standard notions assumed from libraries).

## Questions the paper invites (and short answers)

- **"Why is this not just transparent decryption?"** It *is* the primitive; we place it inside
  a revocation/expiry lifecycle and apply it to federated break-glass with emergency-scoped
  search. Our log is weaker (no proofs, trusted).
- **"What do you actually prove?"** Nothing formally. We *test* eleven claims with negative
  tests (35 system-level + 18 module-level), plus wire checks.
- **"Does the log prevent the audit service from lying?"** No. It is trusted.
- **"Where is the novelty if each part exists?"** The combination, implemented and tested.
  The paper says it claims *only* the combination.
- **"What if I steal the custodian's memory?"** You get shares 1 of every record and every
  persona's keys (limit 5), but you still need an audit share to reach three, so the audit
  service's commit still gates opening.
- **"Why GF(2^256+297)?"** A 257-bit prime larger than any 256-bit secret block, so each
  32-byte block is one field element.
- **"What changed between design and implementation?"** 2-of-3 became weighted 3-of-4 (ADR-0089);
  Expired→Revoked added (ADR-0058); consent kept out of the lifecycle; PRE found bidirectional
  and unused; "no plaintext on the wire" narrowed to TLS only (ADR-0073).

## Glossary

| Term | Meaning |
|---|---|
| **DEK** | Data-encryption key: one random AES-256 key per record |
| **K_E** | The record's 256-bit emergency key, Shamir-split 3-of-4 |
| **Policy root secret** | 32-byte secret that wraps the DEK; rebuilt through the policy tree |
| **Emergency Assertion** | Signed, one-time statement naming patient/clinician/facility/reason |
| **Custodian** | Shared process acting as every persona's key agent; holds share x=1 |
| **Home authority** | The attribute authority that issued the patient's `owner` credential; holds x=2 |
| **Gate** | Facility-side code that combines three shares, unwraps the DEK, delivers it |
| **Full rotation** | New DEK, policy root, emergency key + shares, search index |
| **Commit-then-release** | The audit service commits the log entry, then returns its shares |
| **Canary** | A known secret value the wire analyser searches for in every encoding |
| **Positive control** | A run where the detector must fire (plain capture), so a clean result is trusted |
| **KEM** | Key encapsulation: a fresh symmetric key only the recipient can recompute |
| **PRE** | Proxy re-encryption (ElGamal, bidirectional, unused in break-glass) |
| **BOLA** | Broken object-level authorisation; claim C9 |
| **Claim** | One of C1 to C11; holds only if every system-level test tagged with it passed |
