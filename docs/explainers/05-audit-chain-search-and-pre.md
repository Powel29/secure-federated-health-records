# 5. The audit chain, emergency-only search, and proxy re-encryption

*Paper: Section VI-D (Hash Chain), Section IX (cost of search), Section VIII
(search leakage), the security-properties table, limitations 10 and 12.*

Three supporting ideas. Each is small once you see the picture.

## A. The audit hash chain

**Idea.** Each log entry contains a fingerprint of the previous one:

```
h_i = SHA-256( enc( h_(i-1), event, t, actor ) )     from a zero-hash genesis
```

```
[genesis: prev = 00..00] -> [entry 1: includes h0] -> [entry 2: includes h1] -> ...
```

Each entry holds `seq`, `prev_hash`, `entry_hash`, the event type and metadata,
the actor, a **correlation id**, a timestamp and an **ECDSA signature**. The fields
are encoded **domain-tagged and length-prefixed** (ADR-0077). Event data is
metadata only: ids and hashes, never shares, DEKs or plaintext.

**Verification** checks, per entry: signature, link (`prev_hash` = previous
`entry_hash`), sequence (+1) and recomputed hash. Edit or delete any old entry and
every later fingerprint stops matching. "Verified from genesis: PASS" on the admin
portal means the whole chain was recomputed from the start (claim **C5**: a
tampered audit entry is detected; test `c5_tampered_db_row`).

- The audit service runs as its **own process**, so "commit before release" is a
  real network boundary and not a function call someone can skip.
- On boot the chain is verified; if that fails nothing else starts.
- **Truncation:** a facility keeps a **high-water mark** of the audit sequence on
  its own disk (ADR-0083) and refuses an entry whose `seq` is not above it. **It
  compares sequence numbers only and verifies no entry signature.**
- **Denials and federation events are logged** too (ADR-0038), and every timer
  transition is logged *first*, then mirrored into the store.
- The chain **names patients by store identifier** (pseudonymous, not anonymous;
  limit 12, ADR-0085): a reader learns which pseudonymous patient was accessed, by
  whom and when. No names or dates of birth.

**Honest limits (13 and 8):** the chain is a **plain hash chain held by a trusted
audit service**. It is tamper-*evident* for stored entries. There are **no proofs of
presence or extension** as in transparent decryption (Ryan; Cheval et al.), so a
compromised audit service could release shares without a durable entry or show
different chains to different parties. "No log entry, no key" holds against everyone
**except the audit service**.

## B. Emergency-only searchable encryption

**Problem.** Records are encrypted, so how does an ER doctor find "anticoagulant"?

**Answer.** Each record has an encrypted index of coded terms. A search token is
derived with **HKDF-SHA-256 from the emergency key** (versioned salt
`search-token-v1`, info = the term; ADR-0027):

```
emergency key --HKDF--> token for "anticoagulant" --> matches the coded term
```

- While the record is Emergency_Open the doctor can search. Revocation and expiry
  rotate the emergency key and **re-derive the tokens**, so **old tokens stop
  matching** (claim **C4**: search capability does not survive the emergency's
  expiry; six system tests, on both stores). The clinician portal shows
  **TOKEN LIVE / TOKEN DEAD**.
- Expiry is also enforced by the server: once `now >= expires_at` the emergency key
  is not handed out, even before the sweep.
- **This is an engineering choice, not new cryptography.** Time-limited keyword
  search delegation is prior art (Yang & Ma). We only tie it to the emergency key.

**Honest limit (security-properties table):** tokens are **deterministic**, so searchable encryption
leaks. Measured results are in file 6: on the plain wire all terms are visible and
response size separates hit, miss and refusal; under TLS the term is hidden but
response sizes still separate them. This is the *search-pattern leakage of
deterministic searchable encryption* (Curtmola et al.). There is **no padding**.
Nothing here is proven.

## C. Key delivery and proxy re-encryption (PRE)

**Problem.** The emergency key opens the record in the store. How do we hand the
data key to a doctor at another hospital?

**Answer, as built:** the facility **unwraps the DEK** with the emergency key and
delivers it to the clinician's **ElGamal public key with a key encapsulation (KEM)**
plus AES-GCM (`src/pre`). **The facility sees the plaintext DEK**; only the
*delivery* is encrypted to the doctor. The same KEM seals shares in transit to the
gate.

```
DEK (unwrapped at the facility) --KEM to Dr. Rao's key--> delivery package
```

The module **also contains an ElGamal re-encryption key** `rk = sk_a * sk_b^-1`, but:

- it is **bidirectional** (it inverts to the reverse key; ADR-0076) and needs both
  secret keys;
- it is **unused**: break-glass skips re-encryption (limit 10);
- it has **no security proof**;
- the group is a **256-bit demonstration parameter**, so benchmarks on it do not
  predict a production-size group;
- a re-encryption that never exposes the DEK to the proxy would need **pairings**
  (future work: pairing-based unidirectional PRE).

In the demo you see this as the `federation.rewrap` audit event and the "delivery
package" the custodian opens for Rao. Subgroup membership is validated on every
input (ADR-0023).

> Older docs and ADRs 0001/0012/0018 call the PRE "unidirectional". **The code is
> bidirectional.** The paper follows the code; so do we.

## D. Federated discovery

Records live in **one semi-trusted store** (ADR-0011). Discovery is a lookup by
**patient index** that returns **record ids only**, never ciphertext. A facility
that holds nothing can still answer. In the portal this is the "run federated
discovery" button. (Cross-facility discovery is also a benchmark row: file 17.)

## Where to point in the code

`src/audit/chain.py`, `src/audit/share_custody.py`; `src/search/`; `src/pre/`;
`src/federation/`. Tests in `tests/security/` cover tamper detection (C5) and dead
tokens after expiry (C4).
