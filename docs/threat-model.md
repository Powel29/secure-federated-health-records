# Threat model

Task P0-4 / T04. Owner: **Ojas**. Draft status — needs Ojas's sign-off before
Phase 0 closes.

This document models the adversaries our system defends against. Per the
external-review disposition (`PROJECT.md` §4B, adopted item "Threat model
conflates adversaries"), the four attackers are treated as **separate** threats
with different capabilities and different consequences — not merged into one
"attacker." Merging them is what hides the interesting result: each is stopped by
a *different* property of the design, and one of them (colluding doctors) is only
partially stopped, which we state honestly.

The system's governing security principle (`ARCHITECTURE.md` §8) frames all of
this: cryptographic authorization decides whether a key can be *reconstructed*;
endpoint authorization decides whether a request should have been *served*. Both
run, the endpoint check first.

---

## 1. Assets

What an adversary wants, in priority order:

- **PHI plaintext** — the decrypted contents of a health record. The whole system
  exists to keep this confidential.
- **Data-encryption keys (DEKs)** — one per record, AES-256-GCM; unwrapping one
  yields a record's plaintext.
- **The emergency key** — reconstructed from the 2-of-3 Shamir gate; unlocks
  break-glass and emergency search for a patient.
- **Attribute keys** — issued by authorities; enough of them satisfy a policy
  tree and reconstruct a DEK's wrapping key.
- **Audit-chain integrity** — the hash-chained log is the evidence base for every
  security claim; silently editing it would break tamper-evidence.
- **Metadata** — who accessed what, when, and that a break-glass occurred. We do
  **not** claim to hide all of this; some leakage is a measured result (§4A,
  searchable-encryption leakage; and break-glass is observable as metadata).

## 2. Trust assumptions (what we grant, so the analysis is honest)

- **Cryptographic primitives are sound.** AES-256-GCM, ECDSA, SHA-256, HKDF, and
  the Shamir scheme are assumed correct; we do not model breaking AES.
- **The HSM/KMS emergency timer is a trusted process** (simulated, ADR-0003). Its
  subversion is a documented limitation (`PROJECT.md` §5 item 2), not something
  this model defends against — a compromised timer could decline to expire an
  emergency key, but expiry is a *signed, logged* rotation, so subversion is
  tamper-evident.
- **Each service holds its own signing key** and its local key/state DB is not
  leaked *except where an adversary below is defined to compromise it.*
- **Endpoints out of scope by decision** (`ARCHITECTURE.md` §8 "Deliberately
  excluded", ADR-0015): no rate-limiting, MFA, session, or transport-confidentiality
  threats — there is no browser-facing public deployment and no user population,
  and inter-service traffic is plain HTTP *by design* so the traffic-analysis
  module (§4A) can prove confidentiality comes from the application layer.

---

## 3. Adversary A — the shared store (honest-but-curious)

**Who.** The single central `store` process (port 8000) that holds every
ciphertext record, every wrapped key, and the coded search index. Central by
design (ADR-0011): one target, but one that holds nothing usable.

**Capabilities.** Reads everything it stores; observes access patterns and timing;
does not deviate from protocol (honest-but-curious). A *fully compromised* store
is also considered: an attacker who dumps the entire database.

**What it cannot get.** It holds **no keys and never sees plaintext**. Records are
AES-256-GCM ciphertext; DEKs are wrapped; the search index is coded. A full dump
yields gibberish. This is the deliberate trade of centralization.

**Residual risk (leakage, not plaintext).** Access patterns, query volume, and
response sizes over the search index — the searchable-encryption leakage profile.
We **measure** this rather than deny it (§4A capture requirement 3); it is a
result reported honestly, as every serious SSE paper does. The store also learns
metadata: which patient has how many records, and that a break-glass occurred.

**Stopped by.** Envelope encryption + the store never being a key custodian.

## 4. Adversary B — a hacked hospital node (compromised facility)

**Who.** One facility node (e.g. `facility-a`, port 8001) fully controlled by an
attacker: its process, its local DB of clinician certs and its home-authority
link, and its signing key.

**Capabilities.** Can forge requests that appear to come from that facility;
present certificates it holds; attempt reads and break-glass; replay captured
requests; try to act for patients or records outside its remit.

**What it cannot get.** It cannot decrypt a record whose policy its held attribute
keys do not satisfy — the cryptographic layer is the backstop
(`ARCHITECTURE.md` §8). It cannot forge a break-glass alone: break-glass needs
**2 of 3** shares, and the audit service's share is released only *after* a log
commit, so a rogue node cannot both stay silent and open a record. Replay is
blocked by one-time IDs on assertions, share requests, and transition events
(consumed-ID store, `ARCHITECTURE.md` §8 "Replay protection"). A forged Emergency
Assertion fails the signature/binding/expiry checks before any share is requested.

**Residual risk.** A compromised node *legitimately* holding attribute keys can
read what those keys authorize — this is not a break, it is the node doing what
its keys permit; revocation (key rotation) is the response. It can also enumerate
patient IDs it can reach; this residual is proven bounded by a test (P5-1),
not a middleware layer (ADR-0015). **Forward-only revocation caveat applies**
(`PROJECT.md` §5 item 1): plaintext the node already decrypted and kept is not
retractable.

**Stopped by.** The threshold gate + logging-as-precondition + replay protection +
per-request cryptographic authorization.

## 5. Adversary C — a rogue attribute authority

**Who.** One of the federated attribute authorities (C6) turned malicious: it can
issue attribute keys, including issuing itself or a confederate attributes it
should not grant.

**Capabilities.** Mints attribute keys for attributes **it owns**; signs under its
authority certificate; participates in cross-facility flows as the patient's home
authority, including holding **Share 2** of the break-glass gate.

**What it cannot get.** It can only mint the attributes **it is the authority
for.** A policy tree draws leaves from *multiple independent authorities*
(`ARCHITECTURE.md` §3), so a single rogue authority cannot satisfy a tree that
requires attributes owned by others — this is the multi-authority property doing
its job. As break-glass Share-2 holder it still holds only **one** of three
shares; it cannot reconstruct the emergency key alone (the tested no-single-party
property, `PROJECT.md` §5 item 3).

**Residual risk.** For records whose policy is satisfiable *entirely* by attributes
this authority owns, a rogue authority can mint its way in — an inherent property
of decentralized attribute issuance, bounded by how policies are authored (don't
let one authority own a whole satisfying set for sensitive records). **New under
ADR-0016:** the patient's home authority issues and holds the patient's own
`owner:<patient_id>` attribute key. A rogue home authority could therefore mint
that owner key and read all of that patient's records. This is a real trust
dependency introduced by patient self-access and must be listed as a limitation
alongside item 3 — the home authority was already trusted with Share 2, so this
does not add a new trusted party, but it does widen what a rogue one can do.

**Stopped by.** Multi-authority policy trees + the 2-of-3 gate (for break-glass).
Partially, honestly, for single-authority-satisfiable policies.

## 6. Adversary D — colluding clinicians (attribute pooling)

**Who.** Two or more clinicians, each holding a *different* legitimate attribute
key, who pool them to satisfy a policy that **none satisfies alone**.

**Capabilities.** Combine attribute keys across users during reconstruction.

**What we claim — and do not claim.** This is the **known limitation** stated up
front in the paper (`PROJECT.md` §5 item 4, `ARCHITECTURE.md` §3). Our
secret-sharing access structure is **not collusion-resistant** the way
pairing-based CP-ABE is: real CP-ABE binds each attribute key to a per-user random
value so keys from different users don't combine; we cannot do that without
pairings, which are off the table for install reasons (ADR-0001, ADR-0002).

**Residual risk.** Two clinicians *can* pool keys to reconstruct a wrapping key
neither could alone. We do not hide this; we state it in the abstract and the
limitations section, and list real CP-ABE as future work. Presenting this
honestly is worth more in the viva than an overclaim that collapses under one
question.

**Stopped by.** Not fully. Documented limitation, with the mitigation being
future-work (pairing-based CP-ABE).

---

## 7. Summary — one property per adversary

| Adversary | Wants | Stopped by | Fully? |
|---|---|---|---|
| A · Shared store (HBC) | PHI from the dump | Envelope encryption; store holds no keys | Yes for plaintext; leakage measured |
| B · Hacked hospital node | Forge reads / break-glass | Threshold gate + log-before-share + replay IDs + crypto authz | Yes, beyond what its own keys permit |
| C · Rogue authority | Mint its way into records | Multi-authority policy trees; 2-of-3 gate | Partial — single-authority policies + ADR-0016 owner key |
| D · Colluding clinicians | Pool keys to satisfy a policy | — | **No** — documented limitation, CP-ABE is future work |

The point of separating them: three different mechanisms carry the defense, and
the fourth is an honest gap. A merged "attacker" would let the collusion gap hide
behind the store's strength.

## 8. Out of scope (by decision, not oversight)

- Breaking the crypto primitives themselves (assumed sound).
- Transport-layer attacks / requiring mTLS — inter-service traffic is plain HTTP
  by design for the traffic-analysis module (§4A); payloads are already encrypted
  (ADR-0015 cut the service-signing and plain-HTTP-guard reflexes).
- Production-web-app threats — rate-limit, CORS, MFA, session, brute-force
  (`ARCHITECTURE.md` §8 "Deliberately excluded").
- A malicious HSM/KMS timer beyond the documented signed-rotation mitigation.
- Real patient data exposure — there is none; synthetic records only.
