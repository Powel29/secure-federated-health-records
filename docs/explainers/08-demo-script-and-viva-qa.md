# 8. Demo script and likely questions

## Before you start

Run everything from the project root. The demo path is **Docker Compose** (full
steps in [00-quick-startup.md](00-quick-startup.md)). For a short emergency window
so the audience does not wait, set the window **before** `up`:

```powershell
docker compose -f deploy/docker-compose.yml down
$env:EMERGENCY_DURATION_SECONDS = "60"
docker compose -f deploy/docker-compose.yml up --build -d
docker compose -f deploy/docker-compose.yml logs -f bootstrap   # wait for: federation is up.
```

The **deployed default window is 4 hours** (`14400`), and a caller may only shorten
it; 60 s is just for the demo. Every start resets the synthetic data. Open two
browser windows at http://127.0.0.1:8000/. Password for every login is `demo1234`
(synthetic, dev-only).

| User | Role | Who they are |
|---|---|---|
| `david` | patient `pat-102` | owns `rec-002` (endocrinology) |
| `alice` | patient `pat-101` | owns `rec-001` (cardiology) |
| `house` | clinician `doc-201` | emergency physician at facility-b |
| `cameron` | clinician `doc-202` | endocrinologist at facility-b |
| `chase` | clinician `doc-301` | cardiologist at facility-a |
| `auditor` | admin | read-only audit view |

> **On-screen wording to talk over:** parts of the portal text still say "two of
> three shares" and "share 3". The system is a **weighted 3-of-4** split with
> **shares 3 and 4** at the audit service (ADR-0089). Say the paper's numbers out
> loud, not the screen's.

## The demo, in about 8 minutes

**1. Records are ciphertext (30 s).** As `david`, open the encrypted records page.
Point out: the portal shows metadata, never keys. (Record *labels* are readable in
the store, limitation in file 7.)

**2. Identification is not authorisation (1 min).** As `house`, "Identify patient".
Search family name `Miller`, DOB `11/20/1965`. One match, nothing auto-selected,
"lookup logged · seq N". Optionally show a miss first to show that even misses are
in the chain. Say: the chain holds the pseudonymous patient id, not the name.

**3. Consent is necessary, not sufficient (1.5 min).** As `house`, request consent
for `rec-002`. As `david`, approve it. As `house`, open the read: **Refused: policy
denied**. Say: "The grant is live but Rao does not hold physician + endocrinology,
so the key cannot be rebuilt."

**4. The right doctor succeeds (1 min).** Repeat as `cameron`: request, david
approves, read succeeds and shows the record.

**5. Break-glass (2.5 min).** As `house`, "Emergency break-glass" for David Miller:
run federated discovery, pick `rec-002`, choose a reason code, declare. Show the
three share cards: **share 1 PRESENTED**, **share 2 NOT REQUESTED**, **shares 3 and
4 RELEASED AFTER SEQ N**. Say: "three shares rebuild the key, and the audit service
always holds two of the four." Then run an emergency search ("glucose"):
**TOKEN LIVE**.

**6. It closes by itself (1 min).** Wait for the countdown. Search again: **TOKEN
DEAD**. The case reads expired. Say: "the timer signed Emergency_Open to Expired,
re-keyed the record, and signed it back."

**7. The evidence (1 min).** As `auditor`: chain **PASS**. Trace the break-glass
correlation id and show the order: shares 3 and 4 committed **before** release,
re-wrap event, then the two timer transitions. As `david`, show the access history
and the notification that Rao opened the record.

**Optional proof from a terminal (Powel):**
`python -m tests.security.claims --table` prints C1 to C11 (all `holds`) and
`python -m tests.security.mutations` shows each control's tests going red when the
control is disabled.

## What can go wrong live

| Symptom | Likely cause | Fix |
|---|---|---|
| "emergency_open -> emergency_open" | The record was already opened this run (a second *open*; a *join* by another clinician from the opening facility is allowed) | Restart the stack for a fresh state, or wait for expiry |
| Break-glass refused, patient mismatch | You selected a different patient than the record's owner | Re-identify `pat-102` and choose `rec-002` |
| Everything slow on first click | Cold start of services | Click once before the audience arrives |
| Portal shows store error | Postgres not reachable | `docker compose ... ps -a` |
| Break-glass hangs/503 after a restart of one service | Keys live in process memory (limits 5, 8) | `down`, then `up --build -d` |

Have the **recorded fallback video** ready. It is mandatory (`WORKFLOW.md` Phase 6).

---

## Likely questions, short answers

**Concept**

1. **What is novel here?** The *combination*, built and tested: revocation,
   break-glass and expiry as signed transitions of one key lifecycle over
   per-record keys; log-gated release of the emergency key applied to federated
   break-glass; and search that exists only during an emergency. **Not** the log
   gate on its own (ADR-0088).
2. **Isn't "no log, no key" already published?** Yes, as accountable or transparent
   decryption (Kroll et al.; Ryan 2017; Cheval, Moreira & Ryan 2023). We
   instantiate it for health-record break-glass, inside the lifecycle. **Their log
   is stronger**: ours is a trusted hash chain with no proofs of presence or
   extension and no formal model.
3. **Why 3-of-4?** No single holder, even the audit service, may open a record, and
   no pair may skip the audit service. The audit service holds **two** of the four
   points, so it is in every opening; the custodian holds share 1 and the home
   authority share 2 as a fallback for a lost share 1 (ADR-0089).
4. **What if the audit service is down?** Break-glass fails closed. That is the
   point (no log, no key) and also limitation 8.
5. **Why not just use CP-ABE?** Install risk (ADR-0001). We built a policy tree over
   Shamir instead and state it is not collusion-resistant and has no proof.
6. **Why a shared store, not one per hospital?** So a record follows the patient.
   The store holds only ciphertext (ADR-0011).
7. **Where is consent in the state machine?** It is not. A patient-signed grant is
   checked at read time when presented; it never moves lifecycle state.
8. **Does opening break-glass change any key?** No. Only revocation and expiry
   rotate. Opening reconstructs `K_E`, unwraps the DEK and delivers it.

**Security**

9. **Can the portal read records?** No. It holds no subject keys and its database
   roles cannot write store tables. Compromising it would not defeat the policy
   tree (claim C11).
10. **What stops replay of a captured break-glass request?** Single-use assertion
    ids, ≤ 15 min lifetime, a consumed-id store at **each** of the facility, audit
    service and home authority (C8). Consumption runs last so forgeries cannot burn
    real ids.
11. **What stops a doctor naming the wrong patient?** The facility checks the
    record against the assertion's patient (ADR-0044); the custodian does too when
    it can load the record. The share holders do not.
12. **Can a revoked doctor still read?** Not new versions: the keys were rotated.
    Anything already decrypted and saved cannot be recalled (limit 1). A revoked
    holder who *kept an attribute key* still satisfies its leaves (limit 9).
13. **What if someone edits the log?** Every later hash stops matching and "verified
    from genesis" fails (C5). Tamper-evident for stored entries; a compromised
    audit service could still lie (limit 13).
14. **Is the emergency expiry pure cryptography?** No. A trusted timer enforces it;
    it is signed and logged, so subversion is visible (limit 2).
15. **What does an eavesdropper see?** Under TLS: that a break-glass happened, where
    and when, and its size (a 4356 B burst); not content. On plain HTTP: record
    plaintext and keys. The claim holds **under TLS only** (limit 11).
16. **Can two colluding clinicians pool keys?** Yes, for the policy tree (limit 4).
    Not for break-glass: that needs three shares including an audit share.
17. **Who signs what?** Patient signs revocations and consent; clinician signs
    assertions and break-glass events (key stays in the custodian); the timer signs
    expiry transitions; the audit service signs log entries.

**Honesty and status**

18. **What are your known limitations?** The thirteen in file 7: forward-only
    revocation, server-enforced expiry, no collusion resistance, shared custodian,
    audit service as trusted single point of availability, bidirectional unused
    PRE, TLS-only wire claim, pseudonymous (not anonymous) chain, and so on.
19. **What did testing find?** Three bugs in an early driver (patient binding, stale
    emergency state after expiry, admin page error) and a fourth from running
    containers separately (cross-facility read 500). All fixed with tests. Then six
    claims that started as strict expected-fails were taken to green.
20. **How strong is the evidence?** C1 to C11 all hold: 35 of 35 system-level tests
    pass; full suite 1006 passed, 2 skipped by design, 0 failed. But we do **not**
    claim every current claim test is shown to go red under mutation (the newest
    mutation log is recorded only in prose).
21. **Which course module did you implement?** Module 7, Traffic Analysis, as
    PyShark code that asserts wire properties, run on real plain and TLS captures.
22. **Where is the scalability evidence?** Cut; stated as a limitation, not implied.
23. **How fast is it?** In-process crypto operations take under a millisecond
    (Shamir combine 0.0097 ms, DEK re-wrap 0.025 ms, library revocation 0.24 ms);
    the HTTP paths take ~240 to 250 ms but describe our request path, not the
    cryptography, and vary between runs.

**Viva-style whole-system checks**

24. **Walk me through an emergency, start to finish.** Identify patient by name and
    DOB (logged). Clinician's custodian signs an Emergency Assertion bound to the
    record and justification, and a break-glass transition event. Custodian presents
    share 1 (or fetches share 2 from the home authority). The audit service
    validates the assertion, **commits** the hash-chained entry, **then** seals and
    returns shares 3 and 4. The facility validates again, checks the patient
    binding, combines three shares into `K_E`, unwraps the DEK, logs the re-wrap
    and delivers the DEK to the clinician by KEM. State moves to Emergency_Open;
    nothing is re-keyed. Search tokens work. The timer expires the window, signs
    Emergency_Open to Expired, runs a full rotation, deposits new shares, and signs
    the return to Granted or Revoked. Old tokens and old shares open nothing.
25. **Which state transitions are illegal, and why does it matter?** Anything outside
    the seven pairs (self-transitions, Granted to Expired, any exit from
    Emergency_Open except to Expired). It stops overlapping windows and a premature
    termination, and makes every access state explicit.
26. **Why does the audit service hold two shares rather than one more party?**
    Weighting is Shamir's own device. It makes the audit commit unconditional (every
    qualifying set includes an audit share) without a fourth organisation.
27. **What would you change with more time?** The future-work list in the paper's
    conclusion: a Merkle log with presence/extension proofs the facility checks; a
    home authority that also logs so break-glass works without the audit service;
    epoch-versioned attribute keys; real CP-ABE and pairing-based unidirectional PRE;
    client-side cryptography in personal key agents; keyed chain pseudonyms;
    home-authority revocation; production-size groups; the cut scalability runs.
