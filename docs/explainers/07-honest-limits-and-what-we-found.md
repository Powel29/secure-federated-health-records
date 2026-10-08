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

**Be precise about fix 2.** It is a stop-gap. The store now says "granted", but
the freshly re-keyed record from expiry is still held only in memory. Full
persistence of that re-keying is open work (ADR-0043, task P5-4). Say so.

## How to tell this story in the viva

"We did not stop at passing tests. We attacked our own system with an automated
driver, found that the patient binding was not enforced and that expiry left a
stale state, fixed both with negative tests, and logged the decision as an ADR."

## What is left (be plain about status)

- Phases 0 to 4 are marked done in `WORKFLOW.md`.
- **Phase 5:** benchmark harness (P5-2), search-leakage analysis (P5-3), edge
  cases including re-key persistence (P5-4), PyShark assertions over both
  captures (P5-5), and the full security suite sign-off (P5-1).
- **Phase 6:** the paper (10 marks, `PROJECT.md` §3), demo rehearsal twice, and a
  recorded fallback video.
- A few Phase 4 items (P4-6, P4-9, P4-10) are built but not ticked in
  `WORKFLOW.md`; the file should be updated so it matches reality.
