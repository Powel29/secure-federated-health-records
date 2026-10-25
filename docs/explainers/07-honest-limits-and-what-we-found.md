# 7. Honest limits, and what our own testing found

*Paper: Section X (Limitations) lists items (1) to (13) "in order" plus "further
limits"; the abstract carries the headline ones. Numbering below matches the
paper, so you can say "limitation 8" and everyone knows which.*

Saying limits first is a strength in a viva. Mention the ones in your area before
you are asked.

## The thirteen caveats (paper Section X)

| # | Limit | The one-line truth |
|---|---|---|
| 1 | **Revocation is forward-only** | Rotation denies future reads; it cannot retract plaintext already decrypted and kept. **Only the patient can revoke**; home-authority revocation is not wired (ADR-0084). |
| 2 | **Expiry is server-enforced, not cryptographic** | A trusted timer (simulated HSM) could decline to expire a key. We reduce this to tamper evidence: expiry is a forced rotation between two timer-signed, audited transitions. |
| 3 | **No single shareholder, including the audit service, can open a record** | Claimed **and tested (C3)**, not assumed. It rests on *share placement*; the gate checks no holder, only that three distinct x are present. |
| 4 | **The access structure is not full CP-ABE** | Shamir over an AND/OR tree with symmetric attribute keys is **not collusion-resistant**; two users can pool keys. No proof. |
| 5 | **One shared process is every user's key agent** | The custodian holds every persona's signing key, PRE key, credentials and share 1, in memory. The threshold is not weakened (share 1 only; the audit service still commits first). |
| 6 | **Expiry rotation is *finished* after a crash or restart, not before** | Sessions are stored without their key; a restarted facility closes them with a fresh full rotation. Until then the record stays closed. A revocation runs the same rotation; if a shareholder is unreachable, the revocation holds but break-glass stays closed until re-keying. |
| 7 | **Unidentified patients get no history** | Break-glass is bound to a patient id chosen by a logged name lookup; the scenario assumes identification, which a real ED often lacks (ADR-0059). |
| 8 | **The audit service is a single point of availability** | Every qualifying share set contains an audit share. Share 2 covers only a lost share 1. An audit restart loses shares 3 and 4 of *every* record until re-keyed; by code reading (not observed) it also gets a new signing key and would refuse a non-empty chain. |
| 9 | **Revoking a credential does not revoke a released key** | One attribute key per authority and value, shared by all holders and never rotated; rotation re-seals under the same keys. |
| 10 | **The PRE is bidirectional, and the gate decrypts** | `rk = sk_a * sk_b^-1` inverts to the reverse key, needs both secret keys, unproven. Break-glass skips re-encryption: the facility unwraps the DEK and sends it by KEM. |
| 11 | **"No plaintext on the wire" holds under TLS only** | On the plain profile, record plaintext and attribute keys cross in the clear. TLS certs are self-signed and server-only, no pinned version/cipher. |
| 12 | **The audit chain is pseudonymous, not anonymous** | It names patients by store id: which pseudonymous patient, by whom, when. |
| 13 | **The audit service is trusted** | Stored-entry tampering is detected (C5), but a compromised audit service could release shares without a durable entry or show different chains. No proofs of presence/extension. |

**Further limits (also in the paper):**

- We **cut the scaling runs** over numbers of patients or facilities. Say it as a
  limitation; do not imply the runs exist.
- The federation is **simulated on one machine**, no real health-information
  exchange or FHIR/HL7; all data is synthetic.
- **No formal model or proof.**
- Federation services use the **PostgreSQL superuser**; only the portal is
  confined by database roles.
- The facility's truncation check compares **sequence numbers, not signatures**.
- The **record payload is encrypted without associated data**; only the DEK
  wrapping binds record, policy and generation.
- The PRE, KEM and share sealing use a **256-bit demonstration ElGamal group**.
- **Record labels are readable in the store** (ADR-0064): a record's title, type,
  author and sensitivity label ("HIV", "mental health") sit beside the ciphertext in
  plain text and are shown to clinicians at discovery. The patient signs them, so a
  store write cannot loosen the rules they set, but anyone who can read the store
  learns the *category* of a record.
- **Local demo, not a production system** (ADR-0047): private keys, emergency
  sessions and some replay caches live in process memory; restarting a key service
  means recreating the federation (which wipes the synthetic data); ports bind to
  loopback only.

## What the paper says it does *not* claim (evidence honesty)

- **Mutation testing** (Section VII-B): 18 mutations, each disabling one control,
  cover C1 to C10; C11 relies on a positive control. The only per-test mutation log
  (2026-10-19, 43 rows, each red under some mutation) **predates the 3-of-4 split**
  and lacks seven of today's claim-tagged tests; the post-split run is recorded only
  in prose. So we **do not claim every current claim test is shown to go red.**
- **HTTP benchmark figures are unstable** (405 ms then 247 ms on the same machine);
  treat them as indicative only.
- **The revocation benchmark** times a library call, not the deployed path (which
  does a full expiry rotation that no benchmark times).
- **Search-leakage multi-run figures** are dated 2026-10-19 (pre-3-of-4).
- **Audit-chain verification** benchmark: the chain length was not recorded.

## What our own testing found (history worth telling)

An early automated driver (`tests/e2e/portal_flows.py`) logged in as the seeded
users, ran the demo flows plus a concurrency run, and found **three real bugs**:

| # | Bug | Why it mattered | Fix |
|---|---|---|---|
| 1 | Break-glass did not check the **patient named in the assertion** against the record | An assertion for patient X opened patient Y's record | Facility refuses a mismatch (403, denial logged, no state change). ADR-0044 |
| 2 | After a time-box expired, the store still said **emergency-open** | State in the chain and state in the store disagreed | Reconciled; later replaced by the proper compare-and-set expiry path (ADR-0050, ADR-0069) |
| 3 | The admin **case-review page crashed** on a break-glass with no portal case | The auditor's own view broke on valid data | Template fixed |

Running each service as its own container then exposed a fourth: compiled policies
and consent lived in one process's memory, so a **cross-facility read returned HTTP
500**. Fixed by storing the encrypted policy layout and signed consent in Postgres
(ADR-0047).

## How the claims went from 5 of 11 to 11 of 11

Phase 5's first security run had **5 of 11 claims** holding, with 6 kept as strict
expected-fails tied to review findings (ADR-0046). Those were then fixed, and a
claim that failed would have stayed at full strength rather than being softened.
The live run of 2026-10-21 on commit `57a1a8c` shows **all eleven hold**:

| Claim | Gap that was closed | By |
|---|---|---|
| C3 | audit/authority released shares to anyone who knew the record id | validation at the share holders (ADR-0067), 3-of-4 (ADR-0089) |
| C4 | expiry rotated nothing in the index | expiry as a full rotation (ADR-0069), crash recovery (ADR-0081) |
| C6 | API let an illegal revoke through | compare-and-set state (ADR-0050) |
| C7 | break-glass event not signed by the clinician | clinician-signed event (ADR-0068) |
| C9 | caller authorised after crypto/DB work | signed service requests (ADR-0066) |
| C10 | authority route released keys without checking the credential | ADR-0052, proof of possession (ADR-0082) |

## How to tell this story in the viva

"We did not stop at passing tests. We attacked our own system with an automated
driver, found that the patient binding was not enforced and that expiry left a
stale state, and then took six known gaps to zero with strict expected-fails that
could not be quietly softened. We still list thirteen limitations ourselves, and the
mutation evidence for the newest tests is recorded in prose only."

## Where we are (status)

- **Evidence the paper reports:** all eleven claims hold in a live run on `57a1a8c`;
  PyShark checks ran on real captures (re-recorded 2026-10-21 on the 3-of-4 code);
  benchmarks are recorded with an `environment.json`; P5-1 to P5-5 are ticked in
  `WORKFLOW.md`. Phases are gated by exit criteria, not dates, so check
  `WORKFLOW.md` before you say a phase gate "passed".
- **Phase 6:** the paper is drafted and built (`paper/build/main.pdf`, 10 pages);
  demo rehearsal (twice) and the recorded fallback video remain.
