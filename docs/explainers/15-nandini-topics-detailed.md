# 15. Nandini's topics in detail

Your slot in `11-independent-topics.md`: about 6 minutes, four topics of about
1.5 minutes each, plus the rubric slides you own (data-flow diagram, benchmark
charts, edge-case results, capture and analyser status) and **you run the live
demo**. Story order: **find the patient, search while the window is open, close
the window, prove what the network saw.**

Your concepts from file 11: HKDF and search tokens, time-boxed expiry.

> **Source of truth:** the IEEE paper (`paper/build/main.pdf`, commit `57a1a8c`).
> Yours: Section V-C (Expiry), VIII (Traffic Analysis, the whole section), IX
> (Implementation and Evaluation: method, benchmarks, expansion), claim C4, and the
> "Search leakage" paragraph. File 17 has every number with its caveat.

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
   of the query, the count, and candidate ids (**no name or date of birth in the chain;
   the store `patient_id` is the pseudonym**, ADR-0085). If the audit service did not
   record it, the page returns **503 and withholds the results**: "every identification
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
  identification. **Limit 7:** an unidentified patient gets only a temporary encounter
  id until staff confirm identity, so the scenario assumes identification, which a real
  emergency department often lacks (ADR-0059).
- The patient directory is in the portal database, not federated.
- Metadata leaks: the store learns which patient has how many records.

**Likely questions.**
- *Why not biometrics/QR?* Out of scope; the decision is logged in ADR-0033.
- *Can a clinician enumerate patients?* Each lookup is logged and bounded by the
  input; bulk enumeration is bounded by test not middleware (ADR-0015).

**Tests.** `tests/federation/`, `tests/portal/` clinician identification tests.

---

## Topic 2. Emergency-only searchable encryption

**One sentence.** During an emergency a clinician can search encrypted records for a term
like "glucose", because the search tokens are derived from the emergency key; when the
emergency key is replaced at expiry, the old tokens stop matching.

**Analogy.** An **index with invisible ink**. The index is readable only with a special
lamp (the emergency key). When the lamp is swapped for a different one at the end of the
emergency, the old index no longer lights up.

### How the token is built (`src/search/service.py`, ADR-0027)

```
token = HKDF-SHA256(
    ikm  = emergency_key,
    salt = b"search-token-v1",
    info = b"health-record-search:" + term,
    length = 32)
```

- **HKDF** turns input key material into uniformly random, domain-separated keys. The
  `info` string separates this use from every other use of the same key.
- The token is **deterministic** in `(emergency_key, term)`. The same term always maps to
  the same token, which makes equality search work (and is where the leakage comes from).
- The `salt` is versioned (`v1`), so a future change is a migration, not a silent break.

### Functions

| Function | Role |
|---|---|
| `derive_search_token(key, term)` | The HKDF above |
| `index_search_term(conn, record_id, key, term)` | Compute and insert the token into `search_index` |
| `search_records(conn, coded_term)` | Find record ids whose index row matches the token |
| `search_records_with_emergency(conn, manager, record_id, term)` | Gets the key from the **active session** via the expiry manager, derives the token, searches |
| `rekey_search_index(conn, record_id, new_key, terms)` | Rebuild a record's index under a new key (part of every full rotation) |

`search_records_with_emergency` calls `expiry_manager.get_active_emergency_key(record_id)`,
which refuses once `now >= expires_at` **even before the sweep runs**. So **no live key,
no token, no search**. The store holds only the coded index; it never sees the term or the
key.

### Claim C4: why search really ends at expiry

C4 = *search capability does not survive the emergency's expiry*. **Six system-level
tests** (both the in-memory store and Postgres) check that: emergency search is
**refused after expiry**; it is **not restored by pre-expiry shares**; and a **restart or
crash mid-window still ends in a rotation**. The reason it holds: at expiry the record
gets a **fresh emergency key, a fresh split and re-derived tokens**, so the old shares
rebuild an old key that matches nothing.

**This is an engineering choice, not new cryptography.** Time-limited keyword-search
delegation over patient records is prior art (Yang & Ma); we only derive the tokens from
the emergency key so search ends at the rotation.

### Leakage, measured and dated (paper Section VIII)

The wire table has **one** search. The multi-search figures come from **two runs dated
2026-10-19, before the 3-of-4 change** (the search module is unchanged), 16 searches on one
record, one refused after expiry. Say the dates.

| What | Plain wire | Under TLS |
|---|---|---|
| Terms / URIs / tokens | all visible | none visible |
| Response size separates hit / miss / refusal | **43 / 34 / 95 B** | **60 / 51 / 112 B** |
| Request record | | term length + 63 B |
| Database link | 15 lookups over 9 distinct tokens, with row counts | n/a (plain only) |
| Timing | median **66.1 ms** over 11 hits vs **66.7 ms** over 4 misses: no hit/miss signal at this sample size (16-core AMD host, not the benchmark machine) | |

Deterministic tokens link repeated searches **within a session** (the search-pattern
leakage of deterministic searchable encryption, Curtmola et al.), but **the three terms
searched across expiry got new tokens**. **There is no padding.**

**Say in 90 seconds.**
"Search tokens come from HKDF over the emergency key, so they exist only while that key is
live; expiry replaces the key and re-derives the index. The store keeps coded tokens and
never the words. The cost is leakage: repeated queries look identical within a session,
and response sizes separate hit, miss and refusal even under TLS. We measured that and
dated the runs rather than hiding it. In the demo, 'glucose' finds the record while the
token is live and finds nothing once it is dead."

**Limits to admit.**
- Deterministic tokens leak search and access patterns; there is no padding; nothing here
  is proven (security-properties table).
- Equality search only.
- Multi-search leakage figures predate the 3-of-4 change.
- *Closed since the first review:* C4's system-level test was once an expected-fail
  because expiry rotated nothing in the index. Expiry is now a full rotation (ADR-0069,
  ADR-0081).

**Likely questions.**
- *Why not use real SSE or ORE?* Scope; HKDF tokens are the simplest construction that
  ties search life to the emergency key.
- *Can the store guess the words?* It sees only tokens. Frequency analysis on deterministic
  tokens is the leakage we describe.
- *Why equality search only?* That is all the demo needs; range or fuzzy search would leak
  more.

**Tests.** `tests/security/test_phase2_search.py`; claim C4 (holds).

---

## Topic 3. Time-boxed expiry and forced re-key

**One sentence.** When the emergency window ends, a timer signs the record out of
Emergency_Open, performs a **full rotation** (new DEK, policy root and emergency key with
a fresh 3-of-4 split, re-derived search tokens), and signs it back to the state it was
claimed from, so nothing the doctor held opens the new ciphertext.

**Analogy.** A **hotel key card that stops working at check-out time**, and the hotel also
**changes the lock** so a copied key is useless.

### The simulated HSM timer: `src/lifecycle/expiry.py`, `EmergencyExpiryManager`

The timer stands in for a hardware security module (ADR-0003). It signs with a
**timer-service key**, never the clinician's or the audit service's key; **each facility
process makes a fresh timer key**.

**On unlock:** `register_session` stores the emergency key, the record as it stands, the
wrapping under the emergency key, and the **baseline wrapping and key** the record returns
to. `expires_at = now + d`: the **deployed default is d = 4 h** (`EMERGENCY_DURATION_
SECONDS=14400`), a caller **may shorten but not extend** it, and **one session per record**
may be active. The library default is 60 s (tests, short demos). A row of **identifiers
(no key)** is persisted at open; if that write fails, the session is not registered.

`get_active_emergency_key` returns the key only if the session exists and is not expired;
it **fails closed even if the sweep has not run yet**.

### The sweep: the order

A monitor checks for due sessions **every 0.5 s**; no administrator acts.

1. **Claim the session** (so a manual call and the monitor cannot rotate twice).
   Not yet expired and not forced: `SessionNotExpiredError` (**no premature-termination
   edge**).
2. Sign and apply **Emergency_Open to Expired** with the timer key (through the state
   machine, so the event id is also burned).
3. **Full rotation:** recover the DEK through the record's policy, mint a fresh DEK,
   re-encrypt, new policy root, new emergency key with a **fresh 3-of-4 split to the same
   holders**, re-derive the search tokens, generation + 1.
4. **Only after the rotation is stored and the new shares are deposited**, sign and apply
   the return to **Granted or Revoked** (the state it was claimed from, so an emergency
   cannot undo a revocation, ADR-0058).
5. **Each timer transition is written to the audit log first** (identifiers, no key
   material), then mirrored into the store by compare-and-set.

**On failure:** retry with backoff **capped at 60 s** while access stays closed, reusing
the already-signed events and the first rotation plan, so it neither re-signs nor mints a
second emergency key.

### Crash and restart (ADR-0081)

At startup a facility reloads its own identifier rows for records still Emergency_Open or
Expired as sessions with **no emergency key** and `expires_at = now`, so nobody can join
them and the next sweep expires them. The rotator then recovers the DEK through the
record's policy (the same path revocation uses); if the store already shows Expired, that
event is signed afresh but **not logged again**. Until then the record stays closed
(limit 6).

### Search dies with it

The emergency key is replaced and the tokens re-derived, so `search_records_with_
emergency` raises for the old session and old tokens match nothing. The portal shows
**TOKEN LIVE** then **TOKEN DEAD**.

**Say in 90 seconds.**
"A timer with its own signing key watches each emergency window. At expiry it signs
Emergency_Open to Expired, runs a full rotation, deposits the new shares, and only then
signs the return to the prior state. No admin action. Nothing that decrypted before can
decrypt the new ciphertext, and old shares and tokens open nothing."

**Limits to admit.**
- **Trusted timer, not pure math (limit 2).** A compromised timer could decline to expire.
  We make that tamper-evident through two timer-signed, audited transitions, not
  impossible. A real deployment uses an HSM (ADR-0003).
- **Forward-only:** plaintext the doctor already read is theirs.
- **Rotation is finished after a crash or restart, not before** (limit 6).
- Python cannot truly zeroize memory.

**Likely questions.**
- *What if the server restarts mid-window?* The keyless identifier row is reloaded, nobody
  can join, the next sweep expires it with a fresh full rotation.
- *Why Expired then Granted, not straight to Granted?* The state machine has no
  Emergency_Open to Granted arrow; passing through Expired forces the rotation step.
- *Who signs?* The timer key, so the chain shows the system, not a person, closed it.

**Tests.** `tests/security/test_phase3_expiry_security.py`, `tests/lifecycle/`,
`tests/security/test_deployment_expiry_state.py`.

---

## Topic 4. Traffic analysis (the required course module)

**One sentence.** We capture our own federation's network traffic on loopback and run
PyShark analysers that assert wire properties, exit non-zero when one fails, and have been
**run on real plain and TLS captures** (all pass).

**Analogy.** A **security camera on the corridor** between offices: we do not trust that
envelopes are sealed; we film them and check, with code, what an onlooker could read.

### The honest framing (changed from the first version)

Plain HTTP is **not** "proof that application-layer encryption protects the data": on the
plain wire the facility encrypts and decrypts server-side, so **record plaintext, the
emergency key and four attribute keys cross in the clear** (6 of 13 canaries hit). Plain
is the **positive control**; the claim is **"no plaintext on the wire holds under TLS only"**
(0 of 13 canaries under TLS; ADR-0073). Even plain shows **no share and no signing key**
(shares travel sealed). TLS is self-signed and server-only with no pinned version/cipher.

### The pieces

| File | Role |
|---|---|
| `wire/capture.py` | Runs the scenario under capture; **allowlisted loopback/Docker-bridge only** (any other interface refused); filtered to the six federation ports plus Postgres; writes `plain.pcap` / `tls.pcap` |
| `wire/canaries.py` | The 13 canaries (record plaintext, DEK, emergency key, shares, attribute keys, a signing key) as raw bytes, hex, base64 and PEM |
| `wire/streams.py`, `http_messages.py` | Reassemble TCP flows and pair requests with responses; **a lost segment fails the check** |
| `wire/checks.py` | The claim checks |
| `wire/analyze_traffic.py` | Entry point; exits non-zero if any check fails; writes JSON and a CSV |
| `wire/analyze_search_leakage.py` | Search leakage profile |

### The results (captured 2026-10-21 at `99092d1`; wire code unchanged in `57a1a8c`)

| # | Property | Plain | TLS | Result |
|---|---|---|---|---|
| 0 | Preconditions | 16 endpoints seen | TLS records only | pass |
| 1 | No plaintext | 6 of 13 canaries hit (control fired) | 0 of 13 | pass |
| 2 | Commit before release | **COMMIT 1.35 ms before response** | n/a | pass |
| 3 | Search leakage | 1 search, 1 term in clear, 43 B response | n/a | pass* |
| 4 | Break-glass as metadata | URI visible; 4314 B request | 4356 B burst, 0 content hits | pass |

*A measurement: it fails only if no search traffic is captured.

- **Commit before release** keys on **share 3** in the release response (share 4 is in the
  same response and not timed separately); it needs the **unencrypted** DB link, so
  plain-only.
- **Break-glass as metadata:** a size-only observer picks the **largest burst to the
  facility** as the unlock; under TLS it learns **that, where, when and how big**, never a
  share, emergency key or DEK.
- Checks are explicit results, not `assert`, so `python -O` cannot strip them.

Run: `python -m wire.analyze_traffic --captures wire/captures` (needs `tshark`/`dumpcap`;
on Windows the Npcap loopback adapter).

**Say in 90 seconds.**
"We capture our own traffic on allowlisted loopback in two profiles, plain and TLS, and a
PyShark analyser reassembles the TCP streams and searches 13 canaries in four encodings.
Plain is the control: it exposes plaintext and four attribute keys, which proves the
detector fires. Under TLS none of the 13 appear. The audit database COMMIT crosses the
wire 1.35 ms before the release response that carries the shares. And a size-only observer
under TLS learns that a break-glass happened and how big it was, but not what it opened."

**Limits to admit.**
- "No plaintext on the wire" holds **under TLS only**; the threat model has no on-path
  attacker.
- Commit ordering and the search check run on the plain capture only.
- The wire table has **one** search; multi-search numbers are from 2026-10-19 (pre-3-of-4).
- Metadata leakage is real and measured, not eliminated; no padding.

**Likely questions.**
- *Is capturing your own traffic a real attack?* It is an observer model: what an
  eavesdropper would learn.
- *Why a database commit on the wire?* The audit service talks to Postgres over TCP, so the
  COMMIT is observable and orders the events.
- *Why canaries?* So detection is mechanical and covers every encoding, not eyeballing.

**Tests.** `tests/wire/` (analyser unit tests and the live-capture test).

---

## Diagrams for your slides

1. **Data-flow diagram level 1 (main).** Actors: clinician, patient, auditor.
   Processes: facility, store, authorities, audit, custodian. Show arrows for
   discovery (ids only), break-glass (assertion, shares), and logs.
2. **Search-token and expiry timeline.** A horizontal line: unlock, TOKEN LIVE,
   expires_at, signed Emergency_Open to Expired, re-key, Expired to Granted, TOKEN
   DEAD.

## The live demo (about 4 minutes, you are the operator)

Setup first: restart the stack with a short window
(`$env:EMERGENCY_DURATION_SECONDS="60"` before `up --build -d`; the deployed default is 4 h);
run one break-glass on another record and let it expire. Note the portal text still says
"two of three shares" in places; say "three of four".

| Step | On screen | What to say |
|---|---|---|
| 1 | `house`: Identify, `Miller`, DOB `11/20/1965`, one match | Lookup is in the chain; no key released |
| 2 | Run federated discovery, pick `rec-002`, choose a reason code | Ids only, never content |
| 3 | Declare: case page with the three share cards (share 1 presented, share 2 not requested, shares 3 and 4 released after seq N) and a countdown | Weighted 3-of-4: the audit service always holds two of the four |
| 4 | Emergency search "glucose": TOKEN LIVE | Token exists because the key does |
| 5 | Window ends: TOKEN DEAD, case reads expired | Timer closed it; full rotation; old tokens match nothing |

Rule: **if a step fails, show that step's screenshot slide.** Do not debug live.

## Rubric slides you own

- **Data-flow diagram** (design).
- **Benchmark charts and analysis** (results; paper Section IX and the latency table).
  Method: **5 untimed warm-ups then 30 timed calls** with `time.perf_counter`; median and
  interpolated p95; no outlier removal or CPU pinning. Machine: Intel64 Family 6 Model 186,
  12 logical cores, 15.6 GB RAM, Python 3.11.9, from `environment.json` (which records no
  commit or library versions; the result files are those committed at `57a1a8c`).

  | Operation | Path | Median ms | p95 ms |
  |---|---|---|---|
  | Shamir combine (3-of-4) | in-process | 0.00970 | 0.0102 |
  | DEK re-wrap (one DEK) | in-process | 0.0248 | 0.0320 |
  | Revocation (library call) | in-process | 0.239 | 0.628 |
  | PRE re-encrypt (demo group) | in-process | 0.165 | 0.189 |
  | Cross-facility discovery | HTTP + DB | 247 | 270 |
  | Emergency search | HTTP + DB | 241 | 262 |
  | Audit chain verification | DB read | 11.4 | 17.3 |

  **Read these with the paper's caveats:** (1) Shamir combine is `combine_shares` alone,
  **not** break-glass latency (which also validates, commits and delivers). (2) Re-wrap is
  one DEK, not a sweep. (3) Revocation is the **library call**; the deployed path is a full
  rotation that **no benchmark times**. (4) PRE re-encrypt is one exponentiation in a
  256-bit demo group and **no deployed path calls it**. (5) The two HTTP rows send signed
  requests over plain HTTP on loopback, each making a **nested signed call to the audit
  service, which writes to PostgreSQL**; they vary between runs (our task log, not re-run,
  records 405 ms then 247 ms), so they are **indicative only** and describe this
  deployment's request path, not the cryptography. (6) Despite the label
  `local-processes`, the six services ran as uvicorn servers in **threads of the
  benchmark's own process**, with PostgreSQL 16 in Docker Desktop on Windows. (7) Audit
  verification reads the whole chain; **the chain length was not recorded**. (8) The
  scaling runs over patients/facilities were **cut**.

  **Ciphertext expansion** is a constant 16 B (the GCM tag): 25 % at 64 B, 6.25 % at 256 B,
  1.5625 % at 1 KiB, 0.39 % at 4 KiB, 0.098 % at 16 KiB. It excludes the 12-byte nonce, two
  48-byte DEK wrappings, the compiled policy, a 66-byte share per x and the search index.
  There is no baseline comparison in the paper; do not invent one.
- **Edge-case results:** `tests/breakglass/test_gate.py::TestOpenEmergencyAccessEdgeCases`
  (partial shares, duplicates, corrupted shares); replayed events done; clock skew is
  handled by the **30 s future-dating check** on assertions and transition events.
- **Capture and analyser status:** the analysers ran on real plain and TLS captures
  (re-recorded 2026-10-21 on the 3-of-4 code); all checks pass; say which are plain-only.

## Cross-cutting rules for you

- End your slot with a hand-off to the demo: "let me show all of this live."
- State your limits unprompted: trusted timer, rotation finished after a crash not
  before, deterministic-token leakage with no padding, indicative-only HTTP figures,
  "no plaintext on the wire" under TLS only.
- Know the whole emergency end to end: you operate it live, so you will be asked.

## Answer-routing

| If asked about | You answer |
|---|---|
| Discovery, identification, search, expiry, wire analysis, benchmarks | Yes |
| State machine, Shamir, policy tree, weighted 3-of-4 gate, revocation | Powel |
| PKI, audit chain, PRE, deployment, threat model | Ojas |
| AES-GCM, envelope, assertion, replay, consent, API | Avaneeth |
