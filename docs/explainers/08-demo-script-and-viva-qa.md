# 8. Demo script and likely questions

## Before you start

```bash
DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/mydb python -m deploy.run_portal_demo --duration 60
```

`--duration 60` makes the emergency window one minute so the audience does not
wait. Restart it fresh before the demo (the schema resets each run). Open two
browser windows. Password for every login is `demo1234` (synthetic, dev-only).

| User | Role | Who they are |
|---|---|---|
| `david` | patient `pat-102` | owns `rec-002` (endocrinology) |
| `alice` | patient `pat-101` | owns `rec-001` (cardiology) |
| `house` | clinician `doc-201` | emergency physician at facility-b |
| `cameron` | clinician `doc-202` | endocrinologist at facility-b |
| `chase` | clinician `doc-301` | cardiologist at facility-a |
| `auditor` | admin | read-only audit view |

## The demo, in about 8 minutes

**1. Records are ciphertext (30 s).** As `david`, open the encrypted records
page. Point out: the portal shows metadata, never keys.

**2. Identification is not authorisation (1 min).** As `house`, "Identify
patient". Search family name `Miller`, DOB `11/20/1965`. One match, nothing
auto-selected, "lookup logged · seq N". Optionally show a miss first (type the
full name in the family field) to show that even misses are in the chain.

**3. Consent is necessary, not sufficient (1.5 min).** As `house`, request
consent for `rec-002`. As `david`, approve it. As `house`, open the read:
**Refused: policy denied**. Say: "The grant is live but House does not hold
physician + endocrinology, so the key cannot be rebuilt."

**4. The right doctor succeeds (1 min).** Repeat as `cameron`: request, david
approves, read succeeds and shows the record.

**5. Break-glass (2.5 min).** As `house`, "Emergency break-glass" for David
Miller: run federated discovery, pick `rec-002`, choose a reason code, declare.
Show the three share cards (share 1 presented, share 3 "released after seq N",
share 2 not requested), the countdown, and run an emergency search
("glucose"): **TOKEN LIVE**.

**6. It closes by itself (1 min).** Wait for the countdown. Search again:
**TOKEN DEAD**. The case reads expired.

**7. The evidence (1 min).** As `auditor`: chain **PASS**. Trace the break-glass
correlation id and show the order: share 3 committed before release,
re-wrap event, then the two timer transitions. As `david`, show the access
history and the notification that House opened the record.

## What can go wrong live

| Symptom | Likely cause | Fix |
|---|---|---|
| "emergency_open -> emergency_open" | The record was already opened this run | Restart the stack for a fresh state, or wait for expiry |
| Break-glass refused, patient mismatch | You selected a different patient than the record's owner | Re-identify `pat-102` and choose `rec-002` |
| Everything slow on first click | Cold start of services | Click once before the audience arrives |
| Portal shows store error | Postgres not reachable | Check `DATABASE_URL` and the container |

Have the **recorded fallback video** ready. It is mandatory (`WORKFLOW.md`
Phase 6).

---

## Likely questions, short answers

**Concept**

1. **What is novel here?** Consent, revocation and emergency access unified as
   one signed key-lifecycle state machine; logging as a cryptographic
   precondition of break-glass; search that exists only during an emergency.
2. **Isn't revocation-by-key-rotation already published?** Yes (arXiv
   2511.17464). Our delta is unifying it with consent and break-glass.
3. **Why 2-of-3?** One party alone (even the audit service) must not be able to
   open a record; two of three keeps emergencies possible if one is unavailable.
4. **What if the audit service is down?** Break-glass fails closed. That is the
   point: no log, no key.
5. **Why not just use CP-ABE?** Install risk (ADR-0001). We built a policy tree
   over Shamir sharing instead and state that it is not collusion-resistant.
6. **Why a shared store, not one store per hospital?** So a record follows the
   patient. The store holds only ciphertext (ADR-0011).

**Security**

7. **Can the portal read records?** No. It holds no keys, and its DB role is
   read-only. Compromising it still would not defeat the policy tree.
8. **What stops replay of a captured break-glass request?** Single-use
   assertion ids, short expiry, a consumed-id store.
9. **What stops a doctor naming the wrong patient?** The patient is signed into
   the assertion and the facility checks it against the record (found and fixed
   during our stress test, ADR-0044).
10. **Can a revoked doctor still read?** Not new versions: the key was rotated.
    Anything already decrypted and saved cannot be recalled.
11. **What if someone edits the log?** Every later hash stops matching and
    "verified from genesis" fails. It is tamper-evident, not tamper-proof.
12. **Is the emergency expiry pure cryptography?** No, a trusted timer enforces
    it; a compromised timer could refuse. It is signed and logged, so subversion
    is visible.
13. **What does an eavesdropper see?** Metadata (an emergency happened,
    sizes, timing), not content. The PyShark analysers assert this.

**Honesty and status**

14. **What are your known limitations?** Forward-only revocation, trusted timer,
    non-collusion-resistant policy tree, shared custodian in the demo, search
    leakage, synthetic data, local-only deployment with in-memory keys (file 7).
15. **What did testing find?** Three bugs (patient binding, stale
    emergency-open after expiry, admin page error); fixed with tests; one fix is
    a stop-gap pending full re-key persistence. Running each service as its
    own container then exposed a fourth: cross-facility reads failed because
    policy and consent lived in one process's memory; now shared through
    Postgres (ADR-0047).
16. **What is not done yet?** Benchmarks, search-leakage analysis, final traffic
    assertions over both captures, edge cases, the paper, rehearsal and the
    fallback video.
17. **Which course module did you implement?** Module 7, Traffic Analysis, as
    PyShark code that asserts wire properties.
18. **Where is the scalability evidence?** Cut to fund the portals; stated as a
    limitation, not implied.

**Viva-style whole-system checks**

19. **Walk me through an emergency, start to finish.** Identify patient, sign
    assertion, audit commits then releases share 3, shares 1 and 3 rebuild the
    emergency key, state moves to Emergency-open, DEK re-wrapped to the doctor by
    PRE, search tokens derived, timer expires, state moves to Expired then
    Granted with a fresh key.
20. **Which state transitions are illegal, and why does it matter?** Anything
    not in the table, for example Emergency-open to Emergency-open. It stops
    overlapping time-boxes and makes every access state explicit.
