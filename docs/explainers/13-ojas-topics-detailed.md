# 13. Ojas's topics in detail

Your slot in `11-independent-topics.md`: about 6 minutes, four topics of about
1.5 minutes each, plus the rubric slides you own (the block diagram and the
implementation status slide). Story order: **who do we trust, what do we write
down, how does a key travel, how is it all deployed and attacked.**

Your concepts from file 11: SHA-256 and the hash chain, ECDSA signatures and
X.509, proxy re-encryption, credential lifecycle.

Each topic has: one sentence, an analogy, the mechanics, code to show, a 90-second
script, the limit to admit, and likely questions.

---

## Topic 1. Identity and credentials

**One sentence.** A doctor from a hospital that has never met the patient can be
trusted because every certificate in the federation chains back to one shared
root, and what the doctor may do is proven by short-lived signed credentials from
the authorities that own each attribute.

**Analogy.** Passports and visas. The **certificate chain** is the passport: it
proves *who you are*, because a government (root) vouches for your embassy
(facility CA) which vouches for you. A **credential** is a visa: it proves *what
you may do* (role, specialty), is signed by the office that owns that permission,
has dates, and can be cancelled.

### Part A: identity (X.509 and ECDSA)

- **ECDSA P-256** is the signature scheme everywhere. A private key signs; anyone
  with the public key verifies. Nobody can sign for you.
- **X.509 certificate** = a public key plus a name, signed by an issuer.
- **Root anchor** (`src/identity/root_anchor.py`, `generate_root_anchor`): a
  self-signed CA, valid 10 years. Only the bootstrap process holds its private
  key; everyone else gets only the certificate.
- **Facility CAs** (`certificates.py`): each facility CA is signed by the same
  root. That single fact is **cross-certification** (ADR-0024): facility B can
  verify a clinician from facility A without ever having enrolled them.
- **Clinician certs** are valid 365 days ("nothing issues forever").

### How a chain is checked: `validate_chain` in `src/identity/chain.py`

Walk from the leaf up to the trusted root. At each link:

1. Validity window of the certificate (not expired, not yet valid).
2. If it is an intermediate, it must carry the **CA flag**. A normal leaf cannot
   sign other certificates.
3. The **issuer name** of the lower cert must equal the **subject name** of the
   one above it.
4. The **signature** must verify against the upper cert's key.
5. The top must terminate at the **exact trusted root** the caller holds, not
   just one that claims `CN=federation-root`. A forged chain would claim the same
   name.

Any broken link raises. There is no "partially valid".

### Part B: permissions (attribute authorities)

`src/authority/issuance.py`:

- **`AttributeAuthority`** owns a namespace of attribute names (for example
  `authority-med` owns `role`, `authority-net` owns `specialty`, `facility`,
  `owner`). Trying to issue outside its namespace raises
  `UnauthorizedAttributeError`. A rogue authority cannot mint another's
  attributes.
- **`issue_credential`** creates a signed `AttributeCredential`: serial, issuer,
  subject, attribute, valid_from, valid_until, status. The signature covers all of
  them, joined with the `0x1f` separator.
- **`verify_credential`** checks, in order: signature first, then status is
  ACTIVE, then not in the revocation registry, then not before `valid_from`, then
  not after `valid_until`. Signature first so a forged credential cannot be used
  to probe status behaviour.
- **`attribute_key`**: each attribute (`role:physician`) has **one 32-byte key**
  per authority, the same for every holder. This is what policy-tree leaves are
  sealed to (Powel's topic 3).
- **`get_attribute_key`**: the **credential-gated release**. It only hands out the
  key after `verify_credential` passes. Expired, revoked, wrong-authority or
  forged credential: no key.
- **`revoke_credential`** writes the serial into the authority's revocation
  registry; effective immediately.
- **`issue_owner_credential`**: the patient's own `owner:<patient_id>` credential
  (ADR-0016), issued by the home authority.

**Say in 90 seconds.**
"Trust starts at one root. Facility CAs and authority certificates chain to it, so
an out-of-network doctor's certificate verifies anywhere. What the doctor may do is
a signed credential from the authority that owns that attribute, with a window and
a revocation registry. The attribute key is released only after the credential
verifies. Wrong signature, expired, revoked: no key."

**Limits to admit.**
- The key is per attribute, not per holder, so keys can be pooled by colluding
  doctors (the not-collusion-resistant limit; say it, Powel also will).
- A rogue **home authority** can mint the patient's `owner` key and read all that
  patient's records (threat model adversary C, ADR-0016).
- **Known gap (claim C10, finding F14):** the authority service's
  `/attribute-keys/author` endpoint releases keys without checking a credential at
  all, so at the service level revocation and expiry are not consulted. The
  *module* (`get_attribute_key`) is correct and tested; the *HTTP route* is the
  hole. Say this plainly before a reviewer finds it.

**Likely questions.**
- *Why is the cross-facility trust a single root?* Simpler for two facilities;
  real federations have multiple roots (ADR-0024, scope).
- *Why sign before checking status?* To avoid giving an attacker an oracle.
- *What stops me issuing myself `role:physician`?* Namespace check plus the
  authority's own signing key.

**Tests.** `tests/security/test_phase2_lifecycle.py` (claim C10 module tests),
`tests/api/test_authority_service.py`.

---

## Topic 2. Audit hash chain and commit-before-release

**One sentence.** Every important event is chained to the previous one with
SHA-256 and signed, and the audit service writes its log entry before it hands over
its piece of the emergency key, so there is no key without a log.

**Analogy.** A **numbered ledger bound with string** where each page starts with a
fingerprint of the previous page. Tearing out or editing a page breaks every
fingerprint after it. The **commit-before-release** rule is a bank teller who
refuses to give you the safe key until they have written your name in the book.

### The chain: `src/audit/chain.py`

Formula: `h_i = SHA-256(h_{i-1} ‖ event ‖ timestamp ‖ actor)`.

- Fields are joined with `0x1f`. The event data is **canonical JSON** (sorted
  keys, no whitespace), so the same event always hashes the same.
- **Genesis** (`create_genesis_entry`): seq 0, previous hash is 32 zero bytes,
  signed by the audit service. Everything roots here.
- **`append_entry`**: reads the current head from the database to get `seq` and
  `prev_hash`. The *caller never supplies them*, so an append can only extend the
  true chain.
- Each entry also carries an **ECDSA signature** over a broader payload that
  includes `seq`, `entry_hash` and `correlation_id`, which the hash formula alone
  does not cover. So changing the correlation id is caught by the signature.
- Entry data is **metadata only**: ids and hashes, never shares, DEKs or
  plaintext (rule 3).

### Verification: `verify_chain` and `verify_full_chain`

Per entry, fail at the first problem, in this order:

1. **Signature** verifies. First, so tampering is reported as forgery.
2. **Link:** `prev_hash` equals the previous `entry_hash`.
3. **Recomputed hash** equals the stored `entry_hash` (else `TamperedEntryError`).
4. **Sequence:** `seq` is previous + 1.

Errors: `InvalidSignatureError`, `ChainBreakError`, `TamperedEntryError`,
`EmptyChainError`. At boot the audit service **verifies the whole chain and
refuses to start if it fails**: "nothing else starts" (ARCHITECTURE §7).

### Commit-before-release: `release_share_after_commit` and `POST /breakglass/release`

`src/audit/share_custody.py` is deliberately small:

```
try:
    with conn.transaction():
        entry = append_entry(...)      # 1. write the log
except Exception:
    raise AuditCommitFailedError       # share never reaches a return
return share, entry                    # 2. only now the share exists as output
```

There is no code path that returns the share without the transaction having
completed. The HTTP wrapper in `src/api/audit_service.py` turns the failure into
**503** with "log commit failed; share was not released". A lock serialises
appends, because the service is the single writer.

`ShareRegistry` (`share_registry.py`) holds share 3 in memory per record id. Reads
do not delete it: a custodian holds a standing share; the safety comes from the
gate on each release, not from the share being single-use.

**Why a separate process?** If the audit logic lived inside a facility process,
"the audit service writes first" would be a function call a reviewer could call a
convention. As its own process behind HTTP it is an enforced boundary.

**Denials and federation events are logged too** (ADR-0038). Not just successes.

**Say in 90 seconds.**
"Each entry's hash includes the previous hash, and each is signed, so editing any
entry breaks the chain from there on. The audit service verifies the whole chain
at boot. For break-glass, it commits the log entry in a transaction and only then
returns share 3. If the commit fails, the caller gets a 503 and no share. Live: as
`auditor`, chain PASS, and the `breakglass_share_released` entry with its sequence
number."

**Limits to admit (important).**
- **Claim C3 / finding F2:** the release endpoint, as built, gives share 3 to any
  caller who knows the record id; it does not itself check an assertion,
  signature or one-time id. The log-before-release ordering is real and tested
  (claim C2 holds), but *who may ask* is not enforced at that endpoint yet. Do not
  overclaim "the audit service checks the assertion". The facility validates the
  assertion first.
- The audit service's key is generated fresh each run in the demo (not persisted).
- A single in-process lock assumes one worker (ADR-0039).

**Likely questions.**
- *Can the audit service rewrite history?* It could, but the chain is verified
  externally with its public key and a rewrite changes hashes and signatures the
  portal and auditors recompute.
- *What if the DB is down?* No commit, no share, 503. Fails closed.
- *Why sign when the hash chain exists?* The hash proves order and integrity but
  anyone could recompute a consistent fake chain; the signature proves who wrote it.

**Tests.** `tests/security/test_phase3_audit_security.py` (claims C2 and C5, need
Postgres), `tests/api/test_audit_service.py`.

---

## Topic 3. Proxy re-encryption and key delivery

**One sentence.** The gate can hand the record key to an emergency doctor without
any server ever holding it in readable form on the way: it is encrypted so that
only the doctor's private key can open it.

**Analogy.** A **sealed envelope addressed to the doctor**. The post office
(proxy) can forward or re-address it using a special transformation, but cannot
open it.

### What PRE is (ElGamal, `src/pre/elgamal.py`, ADR-0012)

- A 256-bit **safe prime** `P = 2q + 1`; we work in the prime-order-`q` subgroup
  with generator `g = 4`.
- Key pair: private `sk` random, public `pk = g^sk mod P`.
- Encrypt a group element `m`: pick random `k`; `c1 = g^k`, `c2 = m · pk^k`.
- Decrypt: `m = c2 · (c1^sk)^-1`.
- **Re-encryption key** from A to B: `rk = sk_a · sk_b^-1 mod q`. The proxy
  computes `c1' = c1^rk`, leaving `c2` unchanged. The result decrypts under B's
  key. The proxy never sees `m`, and `rk` only works one way (A to B).
- **Key encapsulation** (`encapsulate_key`): choose a random group element, encrypt
  it under the recipient's `pk`, and derive a **32-byte symmetric key** from it
  with HKDF. This gives a fresh AES key only the recipient can recompute with
  `decapsulate_key`.

**Subgroup validation (ADR-0023).** `_is_subgroup_member` rejects any public key or
`c1` that is not in the order-`q` subgroup, to block small-subgroup attacks on a
hand-rolled ElGamal. This was a real review finding.

### How it is used in break-glass

The gate (`breakglass/gate.py`, step 4) calls `encapsulate_key(clinician_pk)` to
get a delivery key, AES-GCM-encrypts the DEK under it with the record id as AAD,
and packs `c1 ‖ c2 ‖ nonce ‖ wrapped_dek` in fixed-length framing.

Your side: **`open_delivery_package`** in `src/pre/delivery.py`. It splits the
blob by fixed offsets, calls `decapsulate_key` with the clinician's private key to
get the delivery key, and AES-GCM-decrypts with `aad = record_id`.

- Too-short blob: `PREDecryptionError`.
- Wrong key, wrong record id, or tampered data: `InvalidTagError`. No partial
  plaintext is ever returned.
- Because the record id is AAD, a package made for one record **cannot** be opened
  as another.

This lives in `pre/` because the rule "no cryptography in route handlers" forbids
the API layer from doing it. The Key Custodian calls it for the clinician.

**Say in 90 seconds.**
"We use ElGamal proxy re-encryption on a 256-bit safe-prime group. For delivery we
encapsulate a fresh AES key under the doctor's public key, wrap the DEK with it,
and bind the record id as associated data. The doctor decapsulates with their
private key and decrypts. Only the doctor can open it, and a package for one
record is useless for another."

**Limits to admit.**
- Our PRE is hand-rolled over a 256-bit group. That is a **demonstration of the
  mechanism**, not production-grade parameters (a 256-bit multiplicative group is
  far below modern security levels). The scheme was shrunk deliberately (ADR-0012).
- The gate uses encapsulation, not a true delegator-to-delegatee transform of an
  existing DEK ciphertext (the gate's own docstring says so). A full re-encryption
  flow would need its own envelope contract.

**Likely questions.**
- *Why ElGamal and not RSA or ECIES?* PRE needs the algebraic structure for the
  re-key trick; ElGamal gives it in a few lines.
- *Does the proxy learn anything?* Not the message or either private key.
- *Is 256 bits enough?* No, for production; call that out.

**Tests.** `tests/pre/`, `tests/security/test_phase1_security.py`.

---

## Topic 4. Deployment, threat model, admin/audit portal

**One sentence.** Seven separate processes, started in a fixed order with a
verified audit chain first, defended against four *different* attackers, and
observed through a read-only auditor view.

**Analogy.** A **bank with separate vaults**. The vault holding the ledger (audit)
is in a different building from the branches (facilities), so a branch cannot
quietly rewrite the ledger. The auditor can read the ledger but has no key to any
vault.

### The seven processes (ARCHITECTURE §7)

| Process | Port | Holds |
|---|---|---|
| `store` | Postgres (host port 55433 in Compose) | Ciphertext, wrapped keys, coded search index. Never plaintext or unwrapped keys |
| `facility-a` | 8001 | Patient's home facility. Clinician certs. No records |
| `facility-b` | 8002 | Out-of-network facility, the demo entry point |
| `authority-med` | 8010 | Attribute keys for `role:*` |
| `authority-net` | 8011 | Attribute keys for specialty, facility, owner |
| `audit` | 8020 | Hash chain and break-glass share 3 |
| `custodian` | 8030 | Each subject's key agent: signing keys, credentials, share 1. Decides nothing |

The three Django portals (one process, port 8000) run beside these and hold no keys. In Docker Compose every port is published on `127.0.0.1` only, and the store needs `POSTGRES_PASSWORD` from the git-ignored `deploy/.env` (ADR-0047).

### Bootstrap order (`deploy/bootstrap.py`, seven steps in the logs)

1. Apply database migrations (policies and consent now live in Postgres, so
   separate facility processes share them: ADR-0047).
2. `generate_federation_pki`: root anchor + facility CA certificates
   (cross-certification follows from the single root).
3. `register_authority` per authority: fetch its public key, root signs a
   certificate for it.
4. Wait for the audit service (initialises the chain).
5. Wait for the facility nodes.
6. Register federation members and seed synthetic data; write
   `deploy/pki/federation.json`.
7. `check_audit_chain` from genesis: **the hard boot precondition**.

Completion is recorded only after seeding and chain verification succeed. A rerun
compares per-process instance IDs and refuses a partial or changed stack with an
instruction to recreate it. The schema reset refuses any non-local database host.

Run it all with `python -m deploy.run_portal_demo`, or with Docker Compose (see file 0).

### Threat model: four separate attackers (`docs/threat-model.md`)

| Attacker | Stopped by | Fully? |
|---|---|---|
| A. Shared store (honest-but-curious, or fully dumped) | Envelope encryption; store holds no keys | Yes for plaintext. Access-pattern leakage is *measured* |
| B. Hacked hospital node | 2-of-3 gate, log-before-share, one-time ids, crypto authorisation | Yes, beyond what its own keys permit |
| C. Rogue attribute authority | Multi-authority trees, 2-of-3 gate | Partial. Single-authority-satisfiable policies and the home-authority `owner` key remain |
| D. Colluding clinicians pooling keys | Nothing | **No.** Documented limitation |

Why separate them: a merged "attacker" would let the collusion gap hide behind the
store's strength. Out of scope by decision: breaking the primitives, transport
attacks (traffic is plain HTTP on purpose for the traffic-analysis module), web
hardening, a malicious HSM timer.

### The admin/audit portal (`portal/admin_audit/views.py`)

Read-only. It reads the store through the `portal_ro` database role (SELECT only)
and asks the audit service to re-verify the chain.

- `home`: chain length, verification result, event counts, open cases.
- `trace`: all entries for a correlation id, with a link-intact check
  (`_links_intact`: each `prev_hash` equals the previous `entry_hash`). This is
  where you show one emergency end to end.
- `federation`: health of all seven processes and what each holds
  (`_PROCESS_HOLDS`).
- It cannot approve access. Registration "approve" only reaches the issuance stub;
  issuance is the authority's job (ADR-0021).

**Say in 90 seconds.**
"Seven processes: store, two facilities, two authorities, audit, custodian. The
audit service starts first and the chain must verify or nothing starts. We model
four attackers separately: the store, a hacked facility, a rogue authority,
colluding doctors, and we say honestly that the fourth is not stopped. The
auditor portal is read-only. Here is the trace for one emergency: PASS, and the
share release with its sequence number."

**Limits to admit.**
- Fresh federation every run; keys are regenerated (ADR-0039).
- Custodian is one shared process standing in for every person's key agent.
- The threat model file still says "Draft status, needs Ojas's sign-off". Sign it
  off or say it is under review.

**Likely questions.**
- *Why plain HTTP between services?* So the traffic-analysis module can prove
  confidentiality comes from the application layer. A verified TLS profile also
  exists (`TLS_ENABLED=true`, per-service keys, trust bundle, no `verify=false`).
- *What does "the portal never decides access" mean in practice?* A Postgres
  permission: `portal/sql/roles.sql` gives it SELECT only.
- *Which attacker is hardest?* D, collusion. Honest answer.

---

## Diagrams for your slides

1. **Block diagram (main).** Seven boxes with ports; arrows labelled with what
   crosses (ciphertext, signed events, share 3). Mark the audit box as a separate
   process.
2. **Commit-then-release sequence.** Facility, audit service, database.
   Request, `BEGIN`, insert entry, `COMMIT`, only then response with share 3.
   Show the failure branch: commit fails, 503, no share.
3. **Hash-chain picture.** Genesis, then entries each with `prev_hash`. Show one
   edited block turning red and every later block failing.

## Your demo

As `auditor`: the chain verifies PASS; open a trace by correlation id and show the
hash links and the `breakglass_share_released` entry with its sequence number.

## Rubric slides you own

**Block diagram (design).** The seven-process diagram above.

**Implementation status.** Modules built, GitHub repo, merged PRs, CI, ADR log
(47 ADRs in `docs/adr/`), ticked `WORKFLOW.md`. P4-9 and P4-10 are ticked; P4-6 is
built but still unticked, so tick it or say so. Mention that the Phase 5 branches
and the full deployment are merged (PR #37, PR #38), CI green.

## Cross-cutting rules for you

- End your slot with a hand-off: "that wire ordering is what Nandini will check in
  the packet capture."
- State the limits in your area yourself: the C3 share-release gap, the C10 route
  gap, the PRE parameter size, collusion.
- If asked about portal tasks you did not write (ownership drift), say "the team
  built it" and be ready to explain it.

## Answer-routing

| If asked about | You answer |
|---|---|
| PKI, certificates, attribute authorities, credential lifecycle | Yes |
| Hash chain, commit-before-release, share custody | Yes |
| PRE, delivery package | Yes |
| Deployment, threat model, auditor portal | Yes |
| State machine, Shamir, policy tree, 2-of-3 gate | Powel |
| AES-GCM, envelope, assertion, replay, API, consent | Avaneeth |
| Search, expiry, discovery, wire analysis, benchmarks | Nandini |
