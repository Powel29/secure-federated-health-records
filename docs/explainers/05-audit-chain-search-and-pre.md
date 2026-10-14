# 5. The audit chain, emergency-only search, and proxy re-encryption

Three supporting ideas. Each is small once you see the picture.

## A. The audit hash chain

**Idea.** Each log entry contains a fingerprint of the previous one:

```
h_i = SHA-256( h_(i-1) || event || timestamp || actor )
```

```
[genesis h0] -> [entry 1: h1 includes h0] -> [entry 2: h2 includes h1] -> ...
```

Change or delete any old entry and every fingerprint after it stops matching.
"Verified from genesis: PASS" on the admin portal means the whole chain was
re-computed from the start and agrees.

- It runs as its **own process** so "commit before release" is a real network
  boundary and not a function call someone can skip.
- On boot, the chain is verified; if that fails nothing else starts.
- Normal reads are logged but not gated on logging. **Only break-glass is
  gated** (log first, then release share 3).
- Denials are logged too (`access_denied` events). That is why your refused
  read appeared in the chain.

**Honest limit:** the chain is tamper-*evident*, not tamper-*proof*. It tells
you something was altered; it cannot stop the audit host being switched off.

## B. Emergency-only searchable encryption

**Problem.** Records are encrypted, so how does an ER doctor find "anticoagulant"?
**Answer.** Each record has an encrypted index of coded terms. A search token is
derived with HKDF from the **emergency key**:

```
emergency key --HKDF--> search token for "anticoagulant" --> match coded term
```

While the record is Emergency-open the doctor can search. When the key is
re-minted at expiry, the old tokens no longer match anything: the capability
died with the key. The clinician portal shows this as **TOKEN LIVE / TOKEN DEAD**.

**Honest limit:** searchable encryption always leaks something (which records
matched, how many results, how big). We *measure* this leakage from captures
(file 6) instead of pretending it is zero.

## C. Proxy re-encryption (PRE)

**Problem.** The emergency key opens the record in the store. How do we hand the
data key to a doctor at another hospital without any server ever seeing it?
**Answer.** A re-encryption key lets a proxy transform a ciphertext addressed to
person A into one addressed to person B **without learning the plaintext**.
Unidirectional ElGamal-style, hand-rolled (`src/pre`, ADR-0012).

```
DEK wrapped for "emergency"  --(re-encryption key)-->  wrapped for Dr. Rao
        proxy sees only ciphertext, both before and after
```

In the demo you see this as the `federation.rewrap` audit event and the
"PRE delivery package" the custodian opens for Rao.

## Federated discovery

Records live in **one semi-trusted store** (ADR-0011). Discovery is a lookup by
**patient index**: "which encrypted records exist for pat-102?" A facility that
holds nothing can still answer, and neither the store nor the asker learns the
contents. In the portal this is the "run federated discovery" button.

## Where to point in the code

`src/audit/chain.py`, `src/audit/share_registry.py`; `src/search/`;
`src/pre/`; `src/federation/`. Tests under `tests/security/` named for each
phase cover tamper detection and dead tokens after expiry.
