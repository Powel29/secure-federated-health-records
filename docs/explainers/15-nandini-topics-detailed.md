# 15. Nandini's topics in detail

Your slot in `11-independent-topics.md`: about 6 minutes, four topics of about
1.5 minutes each, plus the rubric slides you own (data-flow diagram, benchmark
charts, edge-case results, capture and analyser status) and **you run the live
demo**. Story order: **find the patient, search while the window is open, close
the window, prove what the network saw.**

Your concepts from file 11: HKDF and search tokens, time-boxed expiry.

---

## Topic 1. Federated discovery and identification

**One sentence.** An out-of-network doctor finds which records a patient has, and
identifies the patient by name and date of birth, without seeing any record
content and without that lookup releasing any key.

**Analogy.** A **library catalogue** that tells you "this person has books 2 and
7" but does not let you open them. Looking the person up is written in a visitor
book.

### Discovery: `src/federation/discovery.py`

`find_record_ids_by_patient(conn, patient_id)` runs

```
SELECT record_id FROM records WHERE patient_id = %s
```

It is **deliberately a projection onto `record_id`**, not `SELECT *`. Returning
`Record` objects would hand the querying facility the ciphertext, nonce and aad,
which the architecture forbids on the discovery path. Discovery "learns nothing
about contents". A caller with real access then fetches the record separately.
The hospital API exposes it as `GET /patients/{patient_id}/records`.

### Why a shared store makes this possible

The `store` is patient-indexed and central by design (ADR-0011). Facility B has no
local copy of a stranger's records; it asks the store which record ids exist, then
proceeds through break-glass.

### Identification: `identify` in `portal/clinician/views.py` (ADR-0033)

Emergency identification is by **family name + date of birth** (optionally a given
name prefix), not QR codes or biometrics. Steps:

1. Validate input (DOB must be a date; family name required).
2. Query `PatientDirectory` with a case-insensitive family name and exact DOB.
3. **Log before showing.** An audit entry `patient_lookup` is appended with a hash
   of the query, the count, and candidate ids. If the audit service did not record
   it, the page returns **503 and withholds the results**: "every identification
   must be in the chain".
4. Ambiguous matches are listed; the clinician picks one (`select_candidate`),
   and that selection is logged too, with the id only accepted if it was in the
   current results.

**Key point to say aloud: identification releases no key.** Knowing the patient's
id is not authorisation. Authorisation still needs the assertion, shares and
policy.

### The synthetic federation

`demo/seed_data.py` (`create_synthetic_dataset`) builds fake patients, records and
credentials; `demo/driver.py` drives them. Logins use the dev-only password
`demo1234`. No real patient data, ever.

**Say in 90 seconds.**
"Discovery returns only record ids, never ciphertext. The doctor identifies the
patient by family name and date of birth, and every lookup is written to the audit
chain before the result is shown; if it cannot be written, the result is withheld.
And finding a patient releases no key: authorisation is separate."

**Limits to admit.**
- Name plus DOB is a weak identifier in a real hospital and ambiguity is real; we
  list candidates and log the choice, and we do not claim it is secure
  identification.
- The patient directory is in the portal database, not federated.
- Metadata leaks: the store learns which patient has how many records.

**Likely questions.**
- *Why not biometrics/QR?* Out of scope; the decision is logged in ADR-0033.
- *Can a clinician enumerate patients?* Each lookup is logged and bounded by the
  input; bulk enumeration is bounded by test not middleware (ADR-0015).

**Tests.** `tests/federation/`, `tests/portal/` clinician identification tests.

---

## Topic 2. Emergency-only searchable encryption

**One sentence.** During an emergency a clinician can search encrypted records for
a term like "glucose", because the search tokens are derived from the emergency
key; when the key dies, so does every token.

**Analogy.** An **index with invisible ink**. The index is readable only with a
special lamp (the emergency key). When the lamp is destroyed at the end of the
emergency, the index is just noise.

### How the token is built (`src/search/service.py`, ADR-0027)

```
token = HKDF-SHA256(
    ikm  = emergency_key,
    salt = b"search-token-v1",
    info = b"health-record-search:" + term,
    length = 32)
```

- **HKDF** is a key derivation function: it turns input key material into
  uniformly random, domain-separated keys. The `info` string separates this use
  from every other use of the same key.
- The token is **deterministic** in `(emergency_key, term)`. The same term always
  maps to the same token, which makes equality search work.
- The `salt` is versioned (`v1`), so a future change is a migration, not a silent
  break.

### Functions

| Function | Role |
|---|---|
| `derive_search_token(key, term)` | The HKDF above |
| `index_search_term(conn, record_id, key, term)` | Compute and insert the token into `search_index` |
| `search_records(conn, coded_term)` | Find record ids whose index row matches the token |
| `search_records_with_emergency(conn, manager, record_id, term)` | Gets the key from the **active session** via the expiry manager, derives the token, searches |
| `rekey_search_index(conn, record_id, new_key, terms)` | Rebuild a record's index under a new key |

`search_records_with_emergency` calls
`expiry_manager.get_active_emergency_key(record_id)`. That raises
`SessionNotFoundError` or `EmergencySessionExpiredError` once the window closes, so
**no key, no token, no search**. The store holds only the coded index; it never
sees the term or the key.

### Leakage, measured not denied

Deterministic searchable encryption leaks: the same query gives the same token;
an observer sees **access patterns, query frequency, response sizes and timing**.
Two records indexed with the same term get identical tokens (ADR-0027). We measure
it from real packet captures: `wire/analyze_search_leakage.py`, output
`bench/results/p53_search_leakage.json`.

**Say in 90 seconds.**
"Search tokens come from HKDF over the emergency key, so they only exist while the
emergency lasts. The store keeps coded tokens and never the words. The cost is
leakage: repeated queries look identical on the wire, and we measured that rather
than hiding it. In the demo, 'glucose' finds the record while the token is live and
returns nothing once it's dead."

**Limits to admit (claim C4, finding F9/D3).** The module test passes (search is
refused after expiry), but the **system test is expected-fail**: *expiry rotates
nothing in the index*, so the pre-expiry shares can reopen the record and
re-derive the same tokens. Say: the session key is dropped, but an attacker who
already had the shares could re-derive tokens. Closing this means re-keying the
emergency key at expiry, which is open work.

**Likely questions.**
- *Why not use real SSE or ORE?* Scope; HKDF tokens are the simplest construction
  that ties search life to the emergency key.
- *Can the store guess the words?* It sees only tokens. Frequency analysis on
  deterministic tokens is the leakage we describe.
- *Why equality search only?* That is all the demo needs; range or fuzzy search
  would leak more.

**Tests.** `tests/security/test_phase2_search.py`; claim C4 (module holds, system
xfail).

---

## Topic 3. Time-boxed expiry and forced re-key

**One sentence.** When the emergency window ends, a timer signs the record out of
Emergency-open, changes the record's key, and signs it back to normal, so the
doctor's access really ends and nothing they held decrypts the new ciphertext.

**Analogy.** A **hotel key card that stops working at check-out time**, and the
hotel also **changes the lock** so a copied key is useless.

### The simulated HSM timer: `src/lifecycle/expiry.py`, `EmergencyExpiryManager`

The timer stands in for a hardware security module (ADR-0003). It has its **own
signing identity**, `system:hsm-timer`, never the clinician's or the audit
service's key.

**On unlock:** `register_session` stores the emergency key, the record as it
stands, the wrapping under the emergency key, and the **baseline wrapping and key**
the record returns to. `expires_at = now + duration`. One active session per
record.

`get_active_emergency_key` returns the key only if the session exists and is not
expired; it **fails closed even if the sweep has not run yet**.

### `expire_session`: the order

1. Find the session. Not yet expired and not `force`: `SessionNotExpiredError`
   (an admin cannot cut a granted window short).
2. **Remove the session from the registry under a lock** so the background
   monitor and a manual call cannot double-rotate.
3. Sign and apply **Emergency-open to Expired** (through Powel's state machine, so
   the event id is also burned).
4. **Rotate:** unwrap the old DEK, decrypt, **mint a fresh DEK**, re-encrypt, wrap
   the new DEK under the baseline key with `generation + 1`.
5. Sign and apply **Expired to Granted**.
6. Call the audit logger for each transition, if configured.
7. **Zeroize best-effort:** overwrite the session's key reference with 32 zero
   bytes.

Triggers: an explicit call, `check_and_expire_due`, or a background thread from
`start_monitor`.

### Search dies with it

The session is gone, so `search_records_with_emergency` raises. Tokens already in
the index can no longer be derived from a live key. The portal shows
**TOKEN LIVE** then **TOKEN DEAD**.

**Say in 90 seconds.**
"A timer with its own signing identity watches each emergency window. At expiry it
signs Emergency-open to Expired, re-encrypts the record under a brand-new key,
wraps it back under the normal policy, and signs Expired to Granted. No admin
action. Nothing that decrypted before can decrypt the new ciphertext, and the search
tokens die with the session."

**Limits to admit.**
- **Trusted timer, not pure math.** A compromised timer could decline to expire.
  We make that tamper-evident through signed, logged events, not impossible. A real
  deployment uses an HSM (ADR-0003).
- **Forward-only:** plaintext the doctor already read is theirs.
- Python cannot truly zeroize memory (documented in the module).
- **Re-key persistence is open work (ADR-0043):** after expiry the new record is
  held in memory. The stale-state fix (ADR-0044) reconciled the state label, and
  ADR-0047 now mirrors the expiry state into the store after the audit append;
  neither persists the re-keyed ciphertext. Say this exactly.
- With `audit_logger=None` expiry events do not enter the chain; the API wires the
  real callback.

**Likely questions.**
- *What if the server restarts mid-window?* Sessions are in memory; this is the
  re-key/persistence gap above.
- *Why Expired then Granted, not straight to Granted?* The state machine has no
  Emergency-open to Granted arrow; passing through Expired forces the re-key step.
- *Who signs?* The timer identity, so the chain shows the system, not a person,
  closed it.

**Tests.** `tests/security/test_phase3_expiry_security.py`,
`tests/lifecycle/`, `tests/breakglass/`.

---

## Topic 4. Traffic analysis (the required course module)

**One sentence.** We capture our own federation's network traffic on loopback and
run PyShark-based analysers that assert four properties about what an observer can
and cannot see.

**Analogy.** A **security camera on the corridor** between offices: we do not
trust that envelopes are sealed; we film them and check, with code, what an onlooker
could read.

### Why plain HTTP, on purpose

Capturing only TLS would prove nothing about our contribution. We capture **plain
HTTP** to show that confidentiality comes from application-layer encryption, then
capture a **TLS profile** separately as defence in depth. TLS certs are
local, self-signed, 90 days, one per service (`wire/tls.py`). We capture only our
own synthetic federation on loopback or the Docker bridge, never campus or shared
networks.

### The pieces

| File | Role |
|---|---|
| `wire/capture.py` | Runs the scenario under capture; loopback only (`is_allowed_interface`); writes `plain.pcap` / `tls.pcap` |
| `wire/canaries.py` | Records secret values the scenario handled (shares, keys, DEKs, PHI) in every encoding, as a manifest |
| `wire/streams.py`, `http_messages.py` | Reassemble TCP flows and pair requests with responses |
| `wire/checks.py` | The four claim checks |
| `wire/analyze_traffic.py` | Entry point; exits non-zero if any claim fails; writes JSON and a CSV |
| `wire/analyze_search_leakage.py` | Search leakage profile |

### The four claims (`wire/checks.py`, ADR-0045)

1. **No plaintext on the wire.** Search every capture for every canary in every
   encoding, plus a denylist of key-carrying JSON fields. Two scopes: `all`
   (neither capture may expose a secret) and `tls` (only TLS must be clean; plain is
   the positive control proving the detector fires; decision D6-b).
2. **Commit-before-release.** In the plain capture, the audit service's database
   `COMMIT` for the release entry crosses the wire **before** the
   `/breakglass/release` response that carries share 3, and share 3 appears nowhere
   else before that response. This is an empirical proof of Ojas's ordering.
3. **Search leakage.** Access pattern, repeats, request and response sizes, timing,
   and whether the query appeared in clear.
4. **Break-glass is metadata, not content.** In plain mode the URI is visible; in
   TLS an observer can still tell a break-glass happened from ports and sizes (we
   validate that against the plain capture), but no share, emergency key or DEK is
   readable.

Checks are explicit (`ClaimResult`), not `assert`, because Python's `-O` strips
asserts (review F18). Run: `python -m wire.analyze_traffic --captures wire/captures`.

**Say in 90 seconds.**
"We capture our own traffic on loopback in two profiles, plain HTTP and TLS, and a
PyShark analyser asserts four properties: no secret in the clear, the audit
database commit crosses the wire before share 3, search leakage is as measured, and
break-glass leaks that it happened but not what it opened. Plain HTTP is deliberate:
it shows the application layer, not the transport, protects the data."

**Limits to admit.**
- **Claim 1 under scope `all` fails by design today** because the plain profile
  carries keys, shares and plaintext in request bodies; the analyser says so
  rather than hiding it. The team decision D6 sets the scope.
- The analyser is built and unit-tested on synthetic captures; it has **not** been
  run on real captures (needs `tshark` and Npcap loopback). Capture is restricted
  to loopback and the Docker bridge (F39, done). Report exactly that, and run it
  first if you can (`10-presentation-split.md`: E4).
- Metadata leakage is real and measured, not eliminated.

**Likely questions.**
- *Is capturing your own traffic a real attack?* It is an observer model: what a
  network eavesdropper would learn.
- *Why a database commit on the wire?* The audit service talks to Postgres over
  TCP, so the COMMIT is observable and orders the events.
- *Why canaries?* So detection is mechanical and covers every encoding, not eyeball.

**Tests.** `tests/wire/` (analyser unit tests), the checks in `wire/`.

---

## Diagrams for your slides

1. **Data-flow diagram level 1 (main).** Actors: clinician, patient, auditor.
   Processes: facility, store, authorities, audit, custodian. Show arrows for
   discovery (ids only), break-glass (assertion, shares), and logs.
2. **Search-token and expiry timeline.** A horizontal line: unlock, TOKEN LIVE,
   expires_at, signed Emergency-open to Expired, re-key, Expired to Granted, TOKEN
   DEAD.

## The live demo (about 4 minutes, you are the operator)

Setup first: restart the stack; run one break-glass on another record and let it
expire.

| Step | On screen | What to say |
|---|---|---|
| 1 | `house`: Identify, `Miller`, DOB `11/20/1965`, one match | Lookup is in the chain; no key released |
| 2 | Run federated discovery, pick `rec-002`, choose a reason code | Ids only, never content |
| 3 | Declare: case page with the three piece cards and countdown | Three shares, a clock |
| 4 | Emergency search "glucose": TOKEN LIVE | Token exists because the key does |
| 5 | Window ends: TOKEN DEAD, case reads expired | Timer closed it; key rotated |

Rule: **if a step fails, show that step's screenshot slide.** Do not debug live.

## Rubric slides you own

- **Data-flow diagram** (design).
- **Benchmark charts with baseline and analysis** (results): `bench/run_benchmarks.py`,
  seven D4 metrics: threshold reconstruction, re-wrap cost, revocation latency,
  PRE re-encryption component, cross-facility latency, emergency search latency,
  audit verification. The committed run (30 iterations) shows medians such as
  Shamir 2-of-3 at about 0.005 ms, revocation at about 0.17 ms, cross-facility at
  about 15 ms, audit verification at about 2.2 ms. **The committed numbers are dated 2026-10-07/08 and have no
  `environment.json`: regenerate with `python -m bench.run_benchmarks` on the demo
  machine before presenting and commit the environment record**, and state the baseline you compare against (for example a
  plain AES-GCM read without the policy path). Also say scalability curves were cut
  to fund the portals (`PROJECT.md` D4).
- **Edge-case results:** `tests/breakglass/test_gate.py::TestOpenEmergencyAccessEdgeCases`
  (partial shares, duplicates, corrupted shares); replayed events done; **clock
  skew awaits a team decision**, say so.
- **Capture and analyser status:** be exact about what has and has not been run.

## Cross-cutting rules for you

- End your slot with a hand-off to the demo: "let me show all of this live."
- State your limits unprompted: the C4 index gap, trusted timer, re-key
  persistence, leakage, and the claim-1 scope decision.
- Know the whole emergency end to end: you operate it live, so you will be asked.

## Answer-routing

| If asked about | You answer |
|---|---|
| Discovery, identification, search, expiry, wire analysis, benchmarks | Yes |
| State machine, Shamir, policy tree, 2-of-3 gate, revocation | Powel |
| PKI, audit chain, PRE, deployment, threat model | Ojas |
| AES-GCM, envelope, assertion, replay, consent, API | Avaneeth |
