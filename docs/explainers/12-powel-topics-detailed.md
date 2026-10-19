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
2-of-3 threshold and emergency key, key rotation and forward secrecy.

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

1. **The log comes before the key.** The emergency key is cut into three pieces
   held by three different parties. The audit service hands over its piece only
   after it has written the log entry. No log entry, no key, no access.
2. **One machine, four states.** Consent, revocation and emergency access are
   four states of the same record (Granted, Revoked, Emergency-open, Expired),
   and every move between them is a signed, one-time event.
3. **The window closes by itself.** When time runs out, the record's key is
   changed, so the doctor's access really ends and does not depend on someone
   remembering to switch it off.

### Objectives, each with a pass condition

An objective is only useful if you can show it holding. Each one below names the
test or measurement that proves it.

| # | Objective (plain words) | How we prove it |
|---|---|---|
| 1 | Break-glass **cannot succeed without a committed log entry**. | Negative test: when the audit service cannot commit, no share is released and the emergency fails closed (claim C2, holds). |
| 2 | **No single party can open a record alone**, not even the audit service. | Tests: one share by itself reveals nothing; two shares rebuild the key (claim C3 module tests hold; the system-level test is still an expected-fail, see limits). |
| 3 | Emergency access **ends on its own**, and the searchable-encryption power dies with it. | Tests: the emergency search token stops working after expiry; the timer signs the close (claim C4: module test holds, the system-level test is an expected-fail). |
| 4 | **Revoking someone really denies their future reads**, and it is fast. | Tests: a revoked clinician cannot decrypt after rotation (claim C1, holds). Benchmark: revocation latency, measured by the harness. Re-run it on the demo machine before quoting a number. |

Supporting objectives, also checkable: a replayed emergency assertion is
refused (C8, holds); a tampered log entry is detected (C5, holds); a patient
login alone never releases a key (C11, holds); an illegal state change is
rejected (C6 module test holds).

### What is in scope and out of scope (so nobody asks "why not X?")

| In scope | Out of scope, on purpose |
|---|---|
| Encrypted records, one key per record | Real hospital data: everything is synthetic |
| The four-state machine with signed events | FHIR / HL7 interoperability (this is a security project, not health informatics) |
| 2-of-3 emergency gate with log-before-release | A machine-learning anomaly detector (cut deliberately) |
| Emergency-only searchable encryption | Real hardware security modules (the timer is simulated and logged) |
| A simulated federation of hospitals and authorities | Scalability curves against patient and facility counts (cut to fund the web portals; stated as a limitation) |

### How to say it in 60 seconds

"If an unconscious patient arrives at a hospital that has never seen them,
nobody can ask for consent. Today the answer is a break-glass button plus a
promise to log it later, and a promise can be skipped. We made the log a
precondition of the key. The emergency key is split three ways and the audit
service only gives up its piece after it has written the log entry, so no log
means no access. Consent, revocation and emergency access are four states of one
machine, every change is signed, and when the time-box ends the key changes so
the access really ends. Our objectives are four things we can test: no key
without a log, no single holder can open a record, the window closes by itself,
and revocation really denies the revoked person. We are honest about what is
still open: five of the eleven security claims hold at system level today and
six are tracked as known gaps."

---

## Topic 1. The key-lifecycle state machine

**One sentence.** Consent, revocation and emergency access are not three features;
they are four states of one machine, and every move between states is a signed,
single-use event.

**Analogy.** A door with four settings: *open by invitation* (Granted), *locked
and re-keyed* (Revoked), *glass broken, fire crew inside* (Emergency-open), *fire
crew's time is over* (Expired). You may only turn the dial along marked arrows,
and each turn is written in a ledger with the signature of whoever turned it.

### The four states and six legal arrows

Defined as `LEGAL_TRANSITIONS` in `src/lifecycle/state_machine.py`:

| From | To | Meaning |
|---|---|---|
| Granted | Revoked | Patient (or home authority) withdraws access |
| Granted | Emergency-open | Break-glass on a record that was normally readable |
| Revoked | Granted | Access re-granted later |
| Revoked | Emergency-open | Break-glass even on a revoked record (the whole point) |
| Emergency-open | Expired | The timer closes the window |
| Expired | Granted | After the forced re-key the record returns to normal |

Everything else is illegal, including self-transitions. Examples: Revoked to
Expired, Granted to Expired, Emergency-open to Revoked. Adding an arrow needs an
ADR, because this table is the spine of the project.

Entering Emergency-open also **requires a reason code** (`_EMERGENCY_TRANSITIONS`).

### What a transition event is

`create_transition_event` does this, in order:

1. `validate_transition(from, to, reason)`: if the pair is illegal or the reason
   is missing, it raises and **no signature is ever produced**.
2. Draw a fresh `event_id` (UUID4) and a 16-byte nonce from `secrets`.
3. Build a canonical payload: event id, record id, from state, to state, actor,
   reason, UTC timestamp, nonce, joined with the ASCII unit separator `0x1f`
   (so fields cannot blur into each other).
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

The consumed-id set can be backed by the facility's database (`ConsumedIdBackend`,
review fix F22), so a restart does not forget which ids were used. A lock makes
two threads unable to both pass the check for the same id (review fix F12).

The five distinct failures: illegal pair, missing reason code, bad signature,
stale from-state, replayed id. Each has its own exception, all fail closed.

**Why a machine at all?** Because the same signed-event mechanism then gives
consent, revocation and break-glass a common audit shape. Reviewers can ask "what
state is this record in and who put it there" and get a cryptographic answer.

**Say in 90 seconds.**
"Four states, six legal arrows, anything else is refused. Every move is a signed
event with a single-use id and a reason code if it enters emergency. We verify the
signature before anything else, check the record is really in the claimed state,
and only then burn the id. I will show it refusing Revoked to Expired, and
refusing a replayed event."

**Limit to admit.** The machine is stateless about records: the caller passes the
current state in. Persistence and the audit entry are the caller's job (ADR-0030).

**Likely questions.**
- *Why verify before consume?* So a forgery cannot burn a real id.
- *What stops me replaying yesterday's valid Granted to Revoked?* The id is
  consumed, and `from_state` would no longer match.
- *Can Emergency-open go straight back to Granted?* No. It must pass through
  Expired, which is what forces the re-key (see Nandini's topic 3).

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
| 0 | `check_revocation_authorization`: only the **patient** or the patient's **home authority** may revoke. A clinician with a valid key and signature is still refused (`UnauthorizedRevocationError`, P3-12). |
| 1 | Decrypt the current payload with the old DEK. |
| 2 | Author a new policy tree: `OR(new clinical policy, owner:<patient_id>)`. The owner leaf is always re-added, so the patient never loses their own record (ADR-0016). |
| 3 | Mint a fresh 32-byte root secret and compile the tree (`compile_policy`). Missing attribute keys raise `PolicyCompileError`. |
| 4 | Mint a fresh DEK and re-encrypt the plaintext. Same `record_id`; identity is preserved, only the keys change. |
| 5 | Wrap the new DEK under the new root secret with `generation = old + 1`. |
| 6 | Create a signed `Granted to Revoked` transition event. |
| 7 | Return a `RevocationResult` (rotated record, wrapping, compiled policy, event, audit payload with ids and counters only). |

The function **returns** everything and persists nothing: no storage handle, no
audit connection. That makes it testable without Postgres and keeps one owner for
persistence. The new root secret is returned only so tests can prove round trips;
the caller must never store it.

### Why this works (forward secrecy)

The new DEK is independent of the old one. A doctor who cached the old DEK, or who
holds old attribute keys, faces new ciphertext under a new key. The old DEK opens
nothing. The `generation` counter lets storage tell a stale wrapping from the
current one.

**Say in 90 seconds.**
"Our revocation is cryptographic. Decrypt, new key, re-encrypt, rebuild the
wrapping without the revoked party, bump the generation, and sign a Granted to
Revoked event. Only the patient or home authority may trigger it. In the demo,
`cameron` reads `rec-002`; we revoke; the same read now fails."

**Limit to admit (say it yourself).** **Forward-only.** It cannot un-read
plaintext the clinician already saved. No cryptographic scheme can. It also needs
the old DEK, so the caller must already hold a policy-satisfying unwrap.

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

**Limit to admit.** **Not collusion-resistant.** Two doctors can pool attribute
keys and together satisfy a tree neither satisfies alone. Real CP-ABE blinds keys
per user. We chose Charm-Crypto's rejection (ADR-0001) and this construction
(ADR-0002, ADR-0026). Say it is future work.

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

## Topic 4. The break-glass gate (2-of-3)

**One sentence.** The emergency key is split into three shares held by three
different parties, any two rebuild it, and the gate refuses fewer than two, so no
single custodian, including the audit service, can open a record alone.

**Analogy.** A nuclear-silo two-person rule, but with three possible keyholders:
the **clinician's facility**, the **patient's home authority**, the **audit
service**. Any two turn their keys together.

### Key and split (`src/breakglass/emergency_key.py`)

- `generate_emergency_key()`: 32 random bytes from the CSPRNG via `crypto_core`
  (rule: all crypto goes through `crypto_core`).
- `split_emergency_key(key)`: `split_secret(key, k=2, n=3)`. Constants:
  `THRESHOLD = 2`, `TOTAL_SHARES = 3`.
- Property: one share reveals nothing about the key.

### The gate (`src/breakglass/gate.py`): `open_emergency_access`

The single choke point where shares become a decryptable DEK:

1. **De-duplicate by x.** Duplicate shares count once. If unique shares < 2,
   raise `InsufficientSharesError` **before any reconstruction is attempted**.
2. Reconstruct the emergency key (`combine_shares`).
3. Unwrap the record's DEK, which is AES-GCM-wrapped under the emergency key.
   A wrong key (tampered shares) fails authentication; nothing is re-wrapped.
4. Re-wrap the DEK for the emergency clinician: PRE `encapsulate_key` creates a
   fresh delivery key under the clinician's PRE public key; the DEK is AES-GCM
   encrypted with the record id as AAD; the blob is packed with **fixed-length
   framing** (32 + 32 + nonce bytes, then ciphertext), because raw binary can
   legitimately contain the `0x1f` separator byte.
5. Emit a signed `to Emergency-open` transition event (needs a reason code).
6. Return emergency key, re-wrapped DEK, and event as a frozen result. The caller
   must not persist the emergency key.

Order matters: **the event is signed last**, so a failed unlock never leaves a
signed "emergency opened" artefact.

### What the gate does not do (know this boundary)

It trusts that the **Emergency Assertion** was already validated (Avaneeth's
topic) and that the **audit service wrote its log entry before releasing its
share** (Ojas's topic). Your gate is the maths; theirs are the preconditions. The
hand-off sentence: "the log-before-release rule is what Ojas will show next."

### Why 2-of-3 and not 3-of-3 or 1-of-1

- 1-of-1: whoever holds it can open any record alone. That is a promise, not a
  control.
- 3-of-3: any one unavailable party blocks an emergency. Unsafe for patients.
- 2-of-3: no single party can act alone, and any one can be offline.

**Say in 90 seconds.**
"The emergency key is 256 bits, split 2-of-3: clinician's facility, home authority,
audit service. Fewer than two unique shares and the gate raises before it touches
the key. With two, we rebuild the key, unwrap the DEK, re-wrap it to the clinician
under PRE, and sign the move to Emergency-open. The audit service alone cannot
open a record; that is claim C3, and we test it."

**Limit to admit.** In the demo, the Key Custodian is one shared process holding
share 1; real clinicians would hold their own keys. The threshold property is
unaffected, but it is a simplification (`07-honest-limits...`).

**Likely questions.**
- *What if two shares are corrupted?* Reconstruction fails or AES-GCM unwrap
  fails; either way, closed.
- *What if a custodian sends the same share twice?* Counted once (dedupe by x).
- *Can two colluding custodians open without an audit entry?* The audit service is
  one of the three, and its policy is to commit first. Two non-audit custodians
  could in principle open; that is why the clinician share is only released after
  a valid assertion and why every release is logged. Be candid about it.

**Tests.** `tests/security/test_phase3_breakglass_security.py` (claim C3),
`tests/breakglass/test_gate.py`.

---

## Diagrams for your slides

1. **UML state diagram (main).** Four states, six arrows labelled with actor and
   whether a reason code is needed. Mark the three "sign + consume id" steps.
2. **Policy tree for `rec-002`.** Root `OR`: left branch clinical `AND`
   (role + facility), right leaf `owner:pat-102`. Annotate "AND = Shamir k-of-k,
   OR = same secret".
3. **2-of-3 diagram.** Three boxes (facility, home authority, audit service) with
   one share each; any two arrows meet at the emergency key; one arrow ends at a
   cross.

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
output before you present. The current status in `10-presentation-split.md` is
5 of 11 claims hold (C1, C2, C5, C8, C11) and 6 are expected-fail against review
findings. The full suite was re-run on 2026-10-09 against Postgres: 643 passed,
1 skipped, 6 expected-fail. Say the numbers plainly rather than rounding up.

## Rubric slides you own

**Problem and objectives (1 mark).** Problem: an unconscious patient at a
hospital that has never seen them; "break-glass then log later" is a promise.
Idea: log first, then key. Four measurable objectives; pull them from
`PROJECT.md`. Scope and out-of-scope (no ML anomaly layer, no FHIR/HL7).

**Test-case table (2 marks, testing).** The 11 claims C1 to C11, each with
statement, module test, system test, status. Name the mutation check as the proof
that the tests are not decorative.

**Bugs found and fixed (testing).** Three, from the stress test driver:

| # | Bug | Fix |
|---|---|---|
| 1 | Assertion for patient X opened patient Y's record | Facility refuses mismatch: 403, denial logged, no state change |
| 2 | Store stayed "emergency-open" after expiry, blocking a second break-glass | Stale state reconciled when the timer holds no session |
| 3 | Admin case-review page crashed on a break-glass with no portal case | Template fixed, tests added |

Merged as PR #35, ADR-0044 (Proposed, awaiting ratification). Be precise: fix 2 is
a state-label fix. Since ADR-0047 the timer mirrors its expiry state into the
store after the audit append, but the re-keyed ciphertext is still not persisted
(open work, ADR-0043). Also mention the six Phase 5 review findings behind the
red claims (file 7).

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
| 2-of-3 gate, emergency key | Yes |
| Hash chain, PKI, PRE internals | Ojas |
| AES-GCM, envelope, assertion, replay store | Avaneeth |
| Search, expiry timer, wire analysis, benchmarks | Nandini |
