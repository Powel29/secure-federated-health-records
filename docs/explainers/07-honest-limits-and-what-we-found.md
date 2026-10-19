# 7. Honest limits, and what our own stress test found

Saying limits first is a strength in a viva. These are from `PROJECT.md` §5
and the work we did on 2026-10-02.

## The limits (say them before you are asked)

1. **Revocation is forward-only.** It denies future reads. It cannot un-read
   plaintext someone already saved.
2. **Expiry is enforced by a trusted timer, not pure math.** A compromised
   timer could decline to expire a session. We make that tamper-evident (signed,
   logged rotation), not impossible. A real deployment would use an HSM.
3. **No single share-holder can open a record**, including the audit service.
   We claim it and test it.
4. **Our policy tree is not full CP-ABE.** Not collusion-resistant: two doctors
   could pool attribute keys. Real CP-ABE is future work.
5. **The Key Custodian is one shared process in the demo.** Real people would
   hold their own keys. The threshold property is unaffected (the custodian holds
   share 1 only), but it is a simplification.
6. **Search leaks metadata** (patterns, sizes). We measure it.
7. **Synthetic data only, simulated federation, simulated HSM.**
8. **Scalability curves were cut** to fund the web portals. State this as a
   limitation rather than implying those runs exist (`PROJECT.md` D4).
9. **The deployment is a local demo, not a production system** (ADR-0047).
   Private keys, emergency sessions and replay caches live in process memory,
   so restarting a key service means recreating the whole federation (which
   wipes the synthetic data). Ports bind to loopback only; the custodian
   trusts local callers; the browser portal is plain HTTP on loopback. There is
   no persistent key custody and no internet-facing authentication.
10. **Unidentified patients cannot be opened** (ADR-0059). Identification is a
   name + date-of-birth lookup, so the demo patient carries an ID card. A
   patient with no ID is a common emergency case we do not handle; the "John
   Doe" flow is deferred (ADR-0033).
11. **Record labels are readable in the store** (ADR-0064). A record's title,
   type, author and sensitivity label ("HIV", "mental health") sit beside the
   ciphertext in plain text and are shown to clinicians at discovery. The
   patient signs them, so a store write cannot loosen the rules they set, but
   anyone who can read the store learns the category of a record without
   decrypting it.

## What the automated stress test found

We wrote an end-to-end driver (`tests/e2e/portal_flows.py`) that logs in as the
seeded users and runs the demo flows plus a concurrency run. It passed the
policy, consent and identification checks, survived parallel load with the chain
still verifying, and found **three real bugs**:

| # | Bug | Why it mattered | Fix |
|---|---|---|---|
| 1 | Break-glass did not check the **patient named in the assertion** against the record. An assertion for patient X opened patient Y's record. | The architecture says an assertion opens "this patient only". | Facility now refuses a mismatch (403, denial logged, no state change). |
| 2 | After a time-box expired, the store still said **emergency-open**, so a second break-glass on that record was refused. | The state in the chain and the state in the store disagreed. | Stale state is reconciled when the timer holds no session. |
| 3 | The admin **case-review page returned a server error** when the chain had a break-glass the portal had no case for. | The auditor's own view crashed on valid data. | Template fixed, tests added. |

Merged as PR #35 with tests and **ADR-0044** (status: Proposed, waiting for the
module owners to ratify).

**Be precise about fix 2.** The deployment now also mirrors each audited timer
transition (`expired`, then `granted`) into the store, so the portal status
follows automatic expiry (ADR-0047). But the freshly re-keyed record is still
not persisted: the custodian supplies a throwaway re-baseline key, and
persisting that result would lock out routine readers. So emergency **search**
does die at expiry, but do not claim persisted post-expiry key rotation or
forward secrecy from it in the deployed demo (`PROJECT.md`, ADR-0043/0044).
Say so.

## What the deployment review found

Running each facility as its own process (Compose) exposed a bug the
in-process tests hid: compiled policies and consent lived in Python
dictionaries, so a **cross-facility read returned HTTP 500**. Fixed by storing
the encrypted policy layout and the signed consent artifacts in Postgres
(no new crypto, no contract change). The same review made bootstrap record
completion only after seeding and chain verification, refuse partial or stale
reruns, switch TLS to verified certificates, require a store password, and
refuse a schema reset against any non-local database. ADR-0047, status
Proposed.

## How to tell this story in the viva

"We did not stop at passing tests. We attacked our own system with an automated
driver, found that the patient binding was not enforced and that expiry left a
stale state, fixed both with negative tests, and logged the decision as an ADR."

## What is left (be plain about status)

- Phases 0 to 4 are marked done in `WORKFLOW.md`.
- **Phase 5 (merged to `main`, gate not passed):** P5-1 security suite
  implemented, 5 of 11 claims green; P5-2 benchmark harness built, numbers to be
  re-run on the demo machine; P5-3 search-leakage measured; P5-4 partial shares
  and replayed events done, **clock skew undecided**; P5-5 analyser built, not run
  on real captures. Eleven team decisions (D1 to D8, CS, F14, F40) are pending.
- **Phase 6:** the paper (10 marks, `PROJECT.md` §3), demo rehearsal twice, and a
  recorded fallback video.
- P4-9 and P4-10 are now ticked in `WORKFLOW.md`; P4-6 (traffic capture setup)
  is built but still unticked.
- Deployment is a local demonstration: the custodian assumes trusted local callers,
  keys are regenerated on every fresh run, the portal is the development server on
  loopback (ADR-0047).
