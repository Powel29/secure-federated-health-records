# 12. Powel's topics in detail

Your slot in `11-independent-topics.md`: about 6 minutes, four topics of about
1.5 minutes each, plus the rubric slides you own (objectives, test-case table,
bugs found, deck assembly and timekeeping). Order of topics follows the story:
**states, then how a key is changed, then who may hold a key, then the emergency
gate.**

Each topic below has: the one-sentence version, the analogy, how it works step by
step, the exact code to show, what to say in 90 seconds, the limit to admit, and
likely questions.

Your concepts from the table in file 11: Shamir secret sharing, policy tree,
weighted 3-of-4 threshold and emergency key, key rotation and forward secrecy.

> **Source of truth:** the IEEE paper (`paper/build/main.pdf`, commit `57a1a8c`).
> Paper sections to know cold: III (threat model), V (lifecycle), VI (break-glass),
> VII (security analysis), X (limitations). Files 16 and 17 map them for revision.

---

## Problem statement and objectives (say this first, in plain words)

### The problem, as a story

A patient is brought unconscious into a hospital they have never visited. The
doctor needs their allergies and medication history in the next few minutes. The
patient cannot give consent, and the hospital has no relationship with the
patient's home hospital.

Health records are private, so they are stored encrypted, and normally only
people the patient has approved can unlock them. That is exactly why the
emergency is hard: the lock works, but nobody can ask the patient for the key.

### How hospitals handle it today, and why that is weak

Most systems add a **"break-glass" button**. The doctor presses it, the record
opens, and the system promises to **write a log entry afterwards**. Three things
go wrong with that:

1. **The log is a promise, not a rule.** Anyone with admin rights can open a
   record and skip or edit the log, and nothing in the system stops them.
2. **The access never really ends.** After the emergency, the doctor, or anyone
   who copied the key, can often still read the record, because nothing changes
   the key.
3. **Consent, revocation and emergency are three separate bolt-on features.**
   Because they do not share one model, they contradict each other. A revoked
   record can end up quietly re-opened, or a state in one place disagrees with
   another.

### One-sentence problem statement

> How can a hospital that has never seen a patient open that patient's
> encrypted record in an emergency, **without the log being optional, without
> any single person or server being able to open it alone, and with the access
> closing by itself afterwards**?

### Our idea in three plain sentences

1. **The log comes before the key.** The emergency key is cut into four shares,
   three of which rebuild it, and the audit service holds two of the four. It hands
   its shares over only after it has validated a signed assertion and written the
   log entry. No log entry, no key, no access.
2. **One machine, four states.** Revocation, break-glass and expiry are signed,
   logged transitions of one key lifecycle (Granted, Revoked, Emergency_Open,
   Expired) over per-record keys. Consent is a separate patient-signed grant checked
   at read time; it does not move the state.
3. **The window closes by itself.** When time runs out, the record is fully
   re-keyed, so the doctor's access really ends and does not depend on someone
   remembering to switch it off.

### Objectives, each with a pass condition

An objective is only useful if you can show it holding. Each one below names the
test or measurement that proves it.

| # | Objective (plain words) | How we prove it |
|---|---|---|
| 1 | Break-glass **cannot succeed without a committed log entry**. | Negative test: when the audit service cannot commit, no share is released and the emergency fails closed (claim C2, holds). On the wire, the COMMIT is seen 1.35 ms before the release response. |
| 2 | **No single party can open a record alone**, not even the audit service. | Tests: a single share, the audit service's two shares, and custodian + home authority together all fail at the gate; the share holders refuse a wrong-record, unsigned, untrusted-CA or replayed assertion (claim C3, holds: 10 system-level tests). |
| 3 | Emergency access **ends on its own**, and the searchable-encryption power dies with it. | Tests: search refused after expiry; pre-expiry shares restore nothing; a restart or crash mid-window still ends in a rotation (claim C4, holds: 6 system-level tests, both stores). |
| 4 | **Revoking someone really denies their future reads.** | Tests: a revoked clinician cannot read after the revoke endpoint, in memory and on Postgres (claim C1, holds). Benchmark: the *library call* takes 0.239 ms median (p95 0.628); the deployed path is a full rotation that no benchmark times. |

Supporting objectives, also checkable: a replayed emergency assertion is
refused (C8); a tampered log entry is detected (C5); a patient login alone never
releases a key (C11); an illegal state change and an invalid signature are rejected
(C6, C7); an unauthorised caller is denied before any crypto or DB work (C9); an
expired or revoked credential releases no key (C10). **All eleven hold** in the live
run; 35 of 35 system-level tests pass.

### What is in scope and out of scope (so nobody asks "why not X?")

| In scope | Out of scope, on purpose |
|---|---|
| Encrypted records, one key per record | Real hospital data: everything is synthetic |
| The four-state machine with signed events | FHIR / HL7 interoperability (this is a security project, not health informatics) |
| Weighted 3-of-4 emergency gate with log-before-release | A machine-learning anomaly detector (cut deliberately) |
| Emergency-only searchable encryption | Real hardware security modules (the timer is simulated and logged) |
| A simulated federation of hospitals and authorities | Scalability curves against patient and facility counts (cut to fund the web portals; stated as a limitation) |

### How to say it in 60 seconds

"If an unconscious patient arrives at a hospital that has never seen them,
nobody can ask for consent. Today the answer is a break-glass button plus a
promise to log it later, and a promise can be skipped. We made the log a
precondition of the key. The emergency key is split four ways, any three rebuild
it, and the audit service holds two, so every opening needs it; it only gives up
its shares after it has validated the signed assertion and written the log entry,
so no log means no key. Revocation, break-glass and expiry are signed transitions
of one four-state machine, and at revocation and expiry the keys change so the
access really ends. Log-gated release is prior art; our contribution is the
combination, and we are weaker than the literature on log strength and have no
formal model. All eleven of our security claims hold in a live run, and we list
thirteen limitations ourselves."

---

## Topic 1. The key-lifecycle state machine

**One sentence.** Consent, revocation and emergency access are not three features;
they are four states of one machine, and every move between states is a signed,
single-use event.

**Analogy.** A door with four settings: *open by invitation* (Granted), *locked
and re-keyed* (Revoked), *glass broken, fire crew inside* (Emergency_Open), *fire
crew's time is over* (Expired). You may only turn the dial along marked arrows,
and each turn is written in a ledger with the signature of whoever turned it.

### The four states and seven legal arrows

Defined as `LEGAL_TRANSITIONS` in `src/lifecycle/state_machine.py`:

| From | To | Meaning |
|---|---|---|
| Granted | Revoked | The patient withdraws access (full rotation). Patient-only in this build (ADR-0084) |
| Granted | Emergency_Open | Break-glass on a record that was normally readable. No rotation |
| Revoked | Emergency_Open | Break-glass even on a revoked record (the whole point). No rotation |
| Revoked | Granted | Legal, but **no code in the repository emits it** |
| Emergency_Open | Expired | The timer closes the window |
| Expired | Granted | After the full rotation the record returns to the state it was claimed from |
| Expired | Revoked | Same, if it was Revoked before; or the patient revokes. A later addition (ADR-0058) |

Everything else is illegal, including self-transitions. Examples: Revoked to
Expired, Granted to Expired, Emergency_Open to Revoked or Granted. There is **no
premature-termination edge** out of Emergency_Open. Adding an arrow needs an ADR,
because this table is the spine of the project. (Six of the seven pairs are the
original design; Expired to Revoked came later.)

Entering Emergency_Open also **requires a reason code** (`_EMERGENCY_TRANSITIONS`),
from a closed enumeration of 13.

### What a transition event is

`create_transition_event` does this, in order:

1. `validate_transition(from, to, reason)`: if the pair is illegal or the reason
   is missing, it raises and **no signature is ever produced**.
2. Draw a fresh `event_id` (UUID4) and a 16-byte nonce from `secrets`.
3. Build the signed bytes: the domain tag `ehr/transition-event/v1` followed by
   event id, record id, from state, to state, actor, reason, UTC timestamp and
   nonce, **each length-prefixed** (ADR-0077), so fields cannot blur into each
   other and a transition signature cannot verify as an assertion.
4. Sign it with the actor's ECDSA-P256 key.

### What happens when an event is applied

`LifecycleStateMachine.apply_transition(current_state, event, public_key)`:

1. **Verify the signature first**, then re-check legality. Signature first means
   a tampered event is reported as tampered, not disguised as a policy error.
2. **State match:** `event.from_state` must equal the record's actual current
   state, else `StateMismatchError`. This stops a valid old event being applied
   to a record that has since moved on.
3. **Consume the event id.** `ConsumedEventIds.consume` succeeds once and raises
   `ReplayedEventError` ever after. It is consumed last on purpose: if it were
   consumed before verification, a forged event could burn a legitimate id.

The deployed facility backs the consumed-id set durably, so a restart does not
forget which ids were used. A lock makes two threads unable to both pass the check
for the same id, and the record store adds its own compare-and-set on the stored
state (ADR-0050).

The five distinct failures: illegal pair, missing reason code, bad signature,
stale from-state, replayed id. Each has its own exception, all fail closed.

**Why a machine at all?** Because the same signed-event mechanism then gives
consent, revocation and break-glass a common audit shape. Reviewers can ask "what
state is this record in and who put it there" and get a cryptographic answer.

**Say in 90 seconds.**
"Four states, seven legal arrows, anything else is refused. Every move is a signed
event with a single-use id and a reason code if it enters emergency. We verify the
signature before anything else, check the record is really in the claimed state,
and only then burn the id. I will show it refusing Revoked to Expired, and
refusing a replayed event."

**Limit to admit.** The machine is stateless about records: the caller passes the
current state in. Persistence and the audit entry are the caller's job (ADR-0030).
Also: `Revoked -> Granted` is legal but never emitted, and the expiry-side
transitions are signed by a timer key, not by a person.

**Likely questions.**
- *Why verify before consume?* So a forgery cannot burn a real id.
- *What stops me replaying yesterday's valid Granted to Revoked?* The id is
  consumed, and `from_state` would no longer match.
- *Can Emergency_Open go straight back to Granted?* No. It must pass through
  Expired, which is what forces the full rotation (see Nandini's topic 3). It returns
  to the state the record was claimed from, so an emergency can never undo a
  revocation.
- *Is consent a state?* No: a patient-signed grant checked at read time; it does not
  move the lifecycle state.

**Tests to point at.** `tests/security/test_phase2_lifecycle.py`, claims C6
(illegal transition rejected) and C7 (bad signature rejected).

---

## Topic 2. Revocation by key rotation

**One sentence.** Revoking someone is not setting a flag in a database; it is
decrypting the record, picking a brand-new key, re-encrypting, and re-sealing that
key so the revoked person is not in the new recipe.

**Analogy.** A flag is a note on a door saying "do not enter" that anyone with a
key can ignore. Rotation is **changing the lock and cutting new keys for the
people who still belong**. The old key is now a piece of metal.

### Step by step: `revoke_record_access` in `src/records/revocation.py`

| Step | Action |
|---|---|
| 0 | `check_revocation_authorization`: the module accepts the **patient** or the patient's **home authority**; a clinician with a valid key and signature is refused (`UnauthorizedRevocationError`, P3-12). **In the deployed build only the patient revokes:** the facility endpoint verifies a patient-signed transition, and home-authority revocation is not wired (ADR-0084). |
| 1 | Decrypt the current payload with the old DEK. |
| 2 | Author a new policy tree: `OR(new clinical policy, owner:<patient_id>)`. The owner leaf is always re-added, so the patient never loses their own record (ADR-0016). |
| 3 | Mint a fresh 32-byte root secret and compile the tree (`compile_policy`). Missing attribute keys raise `PolicyCompileError`. |
| 4 | Mint a fresh DEK and re-encrypt the plaintext. Same `record_id`; identity is preserved, only the keys change. |
| 5 | Wrap the new DEK under the new root secret with `generation = old + 1`. |
| 6 | Create a signed `Granted to Revoked` transition event (patient's key, inside the custodian). |
| 7 | Return a `RevocationResult` (rotated record, wrapping, compiled policy, event, audit payload with ids and counters only). |

The function **returns** everything and persists nothing: no storage handle, no
audit connection. That makes it testable without Postgres and keeps one owner for
persistence. The new root secret is returned only so tests can prove round trips;
the caller must never store it.

### Library call versus the deployed path (paper Section IX)

`revoke_record_access` is the **library call**, and it is what the benchmark times
(0.239 ms median). The **deployed facility revokes through the full expiry-style
rotation**: new DEK and policy root, **a fresh emergency key split 3-of-4 to the same
holders, and re-derived search tokens**, with persistence, audit and HTTP. No
benchmark times that path; say so. A revocation can leave break-glass closed until
re-keying if a shareholder is unreachable (limit 6).

### Why this works (forward secrecy)

The new DEK is independent of the old one. A doctor who cached the old DEK, or who
holds old attribute keys, faces new ciphertext under a new key. The old DEK opens
nothing. The `generation` counter lets storage tell a stale wrapping from the
current one.

**Say in 90 seconds.**
"Our revocation is cryptographic. Decrypt, new key, re-encrypt, rebuild the
wrapping without the revoked party, bump the generation, and sign a Granted to
Revoked event. Only the patient can trigger it in this build. In the demo,
`cameron` reads `rec-002`; we revoke; the same read now fails."

**Limit to admit (say it yourself).** **Forward-only.** It cannot un-read
plaintext the clinician already saved. No cryptographic scheme can. And **revoking a
credential does not revoke a released attribute key** (limit 9): the key is shared by
every holder of the attribute and never rotated, so a revoked holder who kept it
still satisfies its leaves. A patient who cannot sign has no revocation path
(ADR-0084).

**Likely questions.**
- *Why not just flip a flag?* Then a compromised server or anyone with the stored
  key still reads. Rotation removes the capability, not the permission.
- *Cost?* One decrypt, one encrypt per record; fine at record scale, heavy for a
  whole patient history (say so, it is a benchmark topic).
- *What if the patient revokes and the clinician is mid-read?* The read in flight
  already has plaintext; that is the forward-only limit.

**Tests.** `tests/security/test_phase3_revocation_security.py`, claim C1 (a revoked
user cannot decrypt after re-wrap). ADR-0036, ADR-0037.

---

## Topic 3. Access structure: policy tree over Shamir

**One sentence.** We replace CP-ABE with a tree of AND and OR nodes where AND is
enforced by Shamir secret sharing and OR by giving every child the same secret, so
"who may read" is a mathematical property of the key, not an if-statement.

**Analogy.** A vault with several padlocks. An **AND** node is "all of these
padlocks must be opened". An **OR** node is "any one of these padlocks opens the
same inner door". Each padlock (leaf) only opens for one particular key.

### Shamir secret sharing (`src/shamir/split.py`)

A secret is the constant term of a random polynomial of degree k-1 over a prime
field. Each share is a point on that polynomial. Any k points determine the
polynomial (Lagrange interpolation at zero gives the secret); k-1 points leave
every possible secret equally likely. That is **information-theoretic** security,
not "hard to break": there is nothing to break.

Implementation points worth knowing:
- `split_secret(secret, k, n)` returns n shares `(x, bytes)` for x = 1..n.
- The secret is length-prefixed (4 bytes) and padded to 32-byte blocks; each
  block gets its own random polynomial.
- `combine_shares` **fails closed**: no shares, fewer than k
  (`InsufficientSharesError`), duplicate x values (`DuplicateShareError`),
  inconsistent or non-multiple lengths (`InvalidShareError`), corrupted length
  header (`SecretSharingError`).

### The policy tree (`src/policy/engine.py`)

`compile_policy(tree, root_secret, attribute_keyring)` pushes a secret down:

| Node | What compile does | What reconstruct needs |
|---|---|---|
| Root | Holds the 32-byte root secret, which wraps the record's DEK | |
| **AND** | Shamir k-of-k split of its secret, one share per child | **Every** child |
| **OR** | Gives **every** child the same secret | **Any one** child |
| **Leaf** | AES-256-GCM-encrypts its secret under the attribute key of the authority that owns that attribute, fresh nonce | The matching attribute key |

Keyring entries are keyed `(authority_id, name, value)`. A key for `role:cardiologist`
from a *different* authority does not open this leaf: the leaf is bound to its
owning authority.

Reading, `reconstruct_root_secret`, walks the tree. A missing or wrong key makes a
leaf return nothing, an AND with any missing child returns nothing, an OR needs one
success. If the root comes back empty you get `PolicyDeniedError`. Never a partial
or default secret. `unwrap_dek_via_policy` then unwraps the DEK with the root.

### Exactly what the paper says about the tree

- Only Leaf, And and Or nodes; **no general k-of-n gate**.
- The root secret is the **DEK wrapping key**; the wrapping's AAD binds **record id,
  policy id and generation**. **Leaf ciphertexts carry no AAD**, so they are not bound
  to their record, position or attribute.
- Attribute keys are symmetric 32-byte keys indexed by **(authority, name, value)**.
- Shamir is over GF(p), **p = 2^256 + 297** (257-bit); shares are **not
  authenticated**: a well-formed wrong share gives a wrong secret that the AES-GCM
  unwrap detects.

### PDP versus PEP

`evaluate_policy` is a cheap boolean (Policy Decision Point): "do these attribute
names satisfy the tree?" Used for UI hints. **It releases nothing.** The enforcing
path (Policy Enforcement Point) is `reconstruct_root_secret`, which only works if
you really hold the keys. This is the heart of "keys decide, not databases".

### Patient self-access

Every tree is authored as `OR(clinical policy, owner:<patient_id>)`
(`author_policy_with_owner`, ADR-0016). The patient reads through the same
decryption path as a doctor. No special back door exists.

### The demo tree for `rec-002`

David's endocrinology record: the clinical branch needs the right role and
facility attributes, so `cameron` (endocrinologist) succeeds while `house`
(emergency physician) is refused **even after consent**. Consent is necessary but
not sufficient; the tree is the second lock.

**Say in 90 seconds.**
"This is our CP-ABE substitute. AND is a Shamir k-of-k split, OR is the same secret
given to each branch, leaves are encrypted to the issuing authority's attribute
key. Reading rebuilds the root from the keys you hold. If you are short, you get a
denial, not a degraded answer. Demo: `house` is refused on `rec-002`, `cameron`
succeeds."

**Limit to admit.** **Not collusion-resistant, and no proof** (limit 4). Two doctors
can pool attribute keys and together satisfy a tree neither satisfies alone.
Pairing-based CP-ABE (Bethencourt et al.) blinds keys per user and prevents this. We
rejected Charm-Crypto (ADR-0001) and chose this construction (ADR-0002, ADR-0026).
Say it is future work.

**Likely questions.**
- *Why not just use CP-ABE?* Library unavailable and unmaintained for our stack;
  the substitute gives the same policy expressiveness minus collusion resistance.
- *Why is Shamir safe if the field is only a prime?* Information-theoretic: fewer
  than k shares are consistent with every secret.
- *What stops someone reusing a share?* Shares only mean something for one
  polynomial; each compile uses fresh randomness.

**Tests.** `tests/security/test_phase2_policy.py`. Claims C10 and C11 touch
credential and patient-login boundaries.

---

## Topic 4. The break-glass gate (weighted 3-of-4)

**One sentence.** The emergency key is split into four shares, any three rebuild it,
and the **audit service holds two of them**, so no single holder (including the audit
service) can open a record and **every opening needs the audit service**, which
commits a log entry before it releases its shares.

**Analogy.** A vault that needs three of four keys, where the **notary holds two** and
the clinician's agent and the patient's home authority hold one each. The notary never
hands over its keys until it has written the visit in the book, and the notary alone
(two keys) cannot open the vault.

### Key and split (`src/breakglass/emergency_key.py`)

- `generate_emergency_key()`: 256-bit random key via `crypto_core`.
- `split_emergency_key(key)`: Shamir with `THRESHOLD = 3`, `TOTAL_SHARES = 4` over
  GF(2^256+297). Holders: **x=1 custodian, x=2 home authority, x=3 and 4 audit**.
- A holder accepts only its own x-set ({1}, {2}, {3,4}), so a misrouted share cannot
  give a custodian-plus-home-authority pair three points (ADR-0089).

| Combination | Points | Opens? |
|---|---|---|
| Custodian alone / home authority alone | 1 | No |
| Audit service alone | 2 | **No** (claim C3) |
| Custodian + home authority | 2 | **No**, and no audit entry exists |
| Audit + custodian | 3 | Yes |
| Audit + home authority | 3 | Yes (fallback when share 1 is lost) |

### The gate (`src/breakglass/gate.py`): `open_emergency_access`

The single choke point where shares become a decryptable DEK:

1. **De-duplicate by x.** If fewer than 3 distinct x, raise `InsufficientSharesError`
   **before any reconstruction is attempted**. The gate checks *only* that three
   distinct x are present: **it checks no share holder.**
2. Reconstruct the emergency key (`combine_shares`).
3. Unwrap the record's DEK (AES-GCM under the emergency key). A wrong key (a
   tampered, unauthenticated share) fails authentication; nothing is re-wrapped.
4. Deliver the DEK to the clinician: a KEM to the clinician's ElGamal key, AES-GCM with
   the record id as AAD, packed with fixed-length framing. **The facility sees the
   plaintext DEK meanwhile.**
5. The signed `-> Emergency_Open` transition (needs a reason code), verified against
   the clinician's certificate, is applied; **no key is rotated**.
6. Return emergency key, delivered DEK and event as a frozen result. The caller must
   not persist the emergency key.

**Why every set contains an audit share** is arithmetic from the placement: the two
other holders have only two points between them. It is **not enforced by the gate**.
That is a deliberate honesty point in the paper.

### What the gate does not do (know this boundary)

It trusts that the **Emergency Assertion** was validated (Avaneeth's topic) and that
the **audit service committed its entry before releasing shares 3 and 4** (Ojas's
topic). Your gate is the maths; theirs are the preconditions.

### Why weighted 3-of-4, and not 2-of-3

The old 2-of-3 gave the home authority a share that was never deposited; had it been,
shares 1 + 2 would open a record with **no audit entry**. A (3,4) split with two points
at the audit service makes the audit commit unconditional and still gives a fallback
for a lost share 1 (ADR-0089, which supersedes ADR-0074). Weighting is just Shamir
with two points for one holder, not a new construction.

**Say in 90 seconds.**
"The emergency key is 256 bits, split three-of-four over a 257-bit prime field: the
custodian holds x=1, the home authority x=2, and the audit service x=3 and 4. Fewer
than three distinct x and the gate raises before it touches the key. Because the
audit service holds two of the four points, every set of three includes an audit
share, so there is no opening without the audit commit, and the audit service alone
cannot open a record. That is claim C3 and we test it, and I will be clear that the
gate checks only the count, the audit-share property comes from share placement."

**Limits to admit.**
- The Key Custodian is one shared process holding share 1 (limit 5).
- **The audit service is a single point of availability** (limit 8): share 2 covers
  only a lost share 1, not a custodian or audit outage, and an audit restart loses
  shares 3 and 4 of every record until re-keyed.
- **The audit service is trusted** (limit 13): a compromised one could release its
  shares without a durable entry.
- Shamir shares are unauthenticated; the GCM unwrap detects a wrong share.

**Likely questions.**
- *What if two shares are corrupted?* Reconstruction gives a wrong key; AES-GCM unwrap
  fails; closed.
- *What if a custodian sends the same share twice?* Counted once (dedupe by x).
- *Can two colluding custodians open without an audit entry?* No: custodian + home
  authority = 2 points. That is the point of the weighting.
- *Why does the home authority not log?* Share 2 opens nothing without shares 3 and 4,
  and the audit service logs every release of those. (Future work: a home authority
  that also logs, so break-glass works without the audit service.)

**Tests.** `tests/security/test_phase3_breakglass_security.py` (claims C2, C3),
`tests/breakglass/test_gate.py`.

---

## Diagrams for your slides

1. **UML state diagram (main).** Four states, six arrows labelled with actor and
   whether a reason code is needed. Mark the three "sign + consume id" steps.
2. **Policy tree for `rec-002`.** Root `OR`: left branch clinical `AND`
   (role + facility), right leaf `owner:pat-102`. Annotate "AND = Shamir k-of-k,
   OR = same secret".
3. **3-of-4 diagram.** Boxes for custodian (x=1), home authority (x=2) and audit
   service (x=3, 4). Any three arrows meet at the emergency key; every valid triple
   passes through the audit box; custodian + home authority ends at a cross.

## Your demo

1. As `david`: `house` is refused on `rec-002` (tree), `cameron` succeeds.
2. Revoke as `david`; `cameron`'s next read fails (rotation).
3. In a terminal:
   - `python -m tests.security.claims --table` shows the 11 claims and which have
     system tests.
   - `python -m tests.security.mutations` switches each control off and checks its
     tests go red. A negative test never seen failing is not known to work.

Be ready for the table to say "NO SYSTEM TEST" if the suite has not been run in
that shell first; run pytest for `tests/security` beforehand and re-check the
output before you present. The paper's live run (2026-10-21, commit `57a1a8c`)
shows **all eleven claims hold, 35 of 35 system-level tests passing, none skipped**;
the full suite gave **1006 passed, 2 skipped (by design), 0 failed**. Say the numbers
plainly rather than rounding up, and add that the mutation log for the newest tests
is recorded only in prose.

## Rubric slides you own

**Problem and objectives (1 mark).** Problem: an unconscious patient at a
hospital that has never seen them; "break-glass then log later" is a promise.
Idea: log first, then key. Four measurable objectives; pull them from
`PROJECT.md`. Scope and out-of-scope (no ML anomaly layer, no FHIR/HL7).

**Test-case table (2 marks, testing).** The 11 claims C1 to C11, each with
statement, system-level and module-level test counts, status (the paper's claims
table has exactly this). Name the mutation check (18 mutations, C1 to C10) as the proof
that the tests are not decorative, and its limit: not re-run per test after 3-of-4.

**Bugs found and fixed (testing).** Three, from the early stress-test driver (plus a
fourth, the cross-facility 500, from running services as separate containers):

| # | Bug | Fix |
|---|---|---|
| 1 | Assertion for patient X opened patient Y's record | Facility refuses mismatch: 403, denial logged, no state change |
| 2 | Store stayed "emergency-open" after expiry, blocking a second break-glass | Stale state reconciled when the timer holds no session |
| 3 | Admin case-review page crashed on a break-glass with no portal case | Template fixed, tests added |

Merged as PR #35, ADR-0044. Be precise: fix 2 was later replaced by the proper
compare-and-set expiry path, and expiry now persists its full rotation before
signing the return to the prior state (ADR-0050, ADR-0069). Also mention the six
Phase 5 review findings behind the formerly red claims (C3, C4, C6, C7, C9, C10),
all closed (file 7).

**Deck assembly and timekeeping (presentation, 1 mark).** You keep time for all
four speakers: about 6 minutes each, then a 4-minute shared demo.

## Cross-cutting rules for you

- Know the whole emergency end to end; the viva may ask anyone (`PROJECT.md` §3).
- End your slot with a hand-off: "that audit commit is what Ojas shows next."
- State the two limits in your area unprompted: **forward-only revocation** and
  **not collusion-resistant**.
- Be clear on ownership drift: if a question touches the P3-10/11/14 portal work
  Avaneeth shipped, say "the team built it" and be ready to explain it anyway.

## Answer-routing

| If asked about | You answer |
|---|---|
| State machine, legal arrows, signed events | Yes |
| Revocation, rotation, forward secrecy | Yes |
| Shamir, policy tree, consent as a gate | Yes |
| Weighted 3-of-4 gate, emergency key | Yes |
| Hash chain, PKI, PRE internals | Ojas |
| AES-GCM, envelope, assertion, replay store | Avaneeth |
| Search, expiry timer, wire analysis, benchmarks | Nandini |
