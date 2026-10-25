# 17. Claims, evidence and every number (cheat sheet)

All values are from the IEEE paper (`paper/`) at repository commit **`57a1a8c`**, live
run of **2026-10-21**, unless a row says otherwise. Quote them exactly; when you are
unsure, quote the caveat with the number. Run the claims table yourself with
`python -m tests.security.claims --table`.

## 1. Headline numbers

| Item | Value |
|---|---|
| Security claims | **11 of 11 hold** (C1 to C11) |
| Claim-tagged tests | **53**: **35 system-level** + **18 module-level**; all 35 system-level pass, none skipped |
| Full test suite (against Postgres) | **1006 passed, 2 skipped, 0 failed** (86.5 s). Both skips test the *missing-dumpcap* path and skip by design when the tool is present |
| Mutation check | **18 mutations** cover C1 to C10; C11 uses a positive control |
| Source size | `src/`: **97 Python files, 16,450 non-blank lines** |
| Language / stack | Python 3.11.9; pyca `cryptography`; FastAPI/uvicorn; PostgreSQL 16; Django |
| Decision log | 89 ADRs (0001 to 0089) |
| Paper | 10 pages, IEEEtran |

## 2. The eleven claims (verbatim from the live run)

Status is computed from the **system-level** tests only. Sys./Mod. = number of system- and
module-level tests tagged with the claim.

| ID | Statement | Status | Sys. | Mod. |
|---|---|---|---|---|
| C1 | A revoked user cannot decrypt after re-wrap | holds | 2 | 2 |
| C2 | Break-glass fails closed when the audit service cannot commit | holds | 1 | 1 |
| C3 | A single share, including the audit service's, cannot open a record | holds | 10 | 4 |
| C4 | Search capability does not survive the emergency's expiry | holds | 6 | 1 |
| C5 | A tampered audit entry is detected by chain verification | holds | 1 | 3 |
| C6 | An illegal state transition is rejected | holds | 1 | 1 |
| C7 | A transition event with an invalid signature is rejected | holds | 2 | 1 |
| C8 | A replayed emergency assertion is rejected, not re-executed | holds | 4 | 1 |
| C9 | An authenticated but unauthorised caller is denied before any crypto or DB work (BOLA) | holds | 3 | 0 |
| C10 | An expired or revoked credential fails validation and releases no key | holds | 4 | 2 |
| C11 | A patient login alone never releases a DEK | holds | 1 | 2 |
| **Total** | | | **35** | **18** |

**Rules for reading it:** a claim holds only if *every* system-level test tagged with it
passed; a skip makes it *unverified*; an expected failure "fails today"; module-level results
never change a status. Two precision points the paper makes: in **C1**, "re-wrap" is a *full
rotation*; in **C3**, the audit service's two shares together are *one short* of the
threshold, and the claim text was written on 2026-10-07, **before** the 3-of-4 split.

## 3. What each claim's tests actually check (abridged from Section VII)

| Claim | The evidence |
|---|---|
| C1 | After revocation through the facility endpoint, **on the in-memory store and on Postgres**, the clinician cannot read |
| C2 | `release_share_fails_closed` makes the audit commit fail → no share; the append runs in one transaction that raises before any share is returned |
| C3 | **Ten tests**: the audit service refuses an assertion for another record, one not signed by the certificate key, one from an untrusted CA, and a replayed one (the home authority, the first two); the facility opens nothing with one share, with custodian + home authority, or with the audit service's two shares |
| C4 | **Six tests**: search refused after expiry; not restored by pre-expiry shares; a restart or crash mid-window still ends in a rotation; on both stores |
| C5 | `c5_tampered_db_row` alters a stored entry and chain verification (signature, link, sequence, hash) fails |
| C6, C7 | C6: `c6_api_refuses_revocation` requests a pair outside the seven legal transitions. C7: a break-glass event verifies against the clinician's certificate; one the clinician did not sign opens nothing |
| C8 | Replay refused at the home authority, at the facility, after a facility restart, and across processes on Postgres; each party keeps its own consumed-id store |
| C9 | A portal may not request an audit share; an unsigned service request is refused; an authenticated but unauthorised caller is stopped before any crypto or DB work. **No module-level test** |
| C10 | Revoked, expired or copied credentials, and requests without a valid credential, release no key |
| C11 | The custodian refuses a patient without an owner credential, and only the home authority issues that key |

## 4. The mutation evidence, and where to stop

- 18 mutations, each disabling one control by monkeypatching, cover C1 to C10; C11 uses a
  positive control. A test passes only if a mutation of its claim turns it red.
- The only per-test mutation log (**2026-10-19, 43 rows, each red under some mutation**)
  **predates the 3-of-4 split** and lacks **seven** of today's claim-tagged tests; the
  post-split run of 2026-10-21 is recorded **only in prose**.
- The runner counts a test whose baseline is skipped as neither caught nor decorative.
- **So:** *we do not claim that every current claim test is shown to go red.*

## 5. Wire results (Section VIII)

Captured 2026-10-21 at commit `99092d1` (capture/analyser/service code unchanged in `57a1a8c`).

| # | Property | Plain | TLS | Result |
|---|---|---|---|---|
| 0 | Preconditions | 16 endpoints seen | TLS records only | pass |
| 1 | No plaintext | 6 of 13 canaries hit (control fired) | 0 of 13 | pass |
| 2 | Commit before release | COMMIT **1.35 ms** before response | n/a | pass |
| 3 | Search leakage | 1 search, 1 term in clear, 43 B response | n/a | pass* |
| 4 | Break-glass as metadata | URI visible; 4314 B request | 4356 B burst; 0 content hits | pass |

\*measurement; fails only if no search traffic is captured.

Search-leakage runs (2026-10-19, **pre-3-of-4**, 16 searches on one record, one refused
after expiry):

| | Plain | TLS |
|---|---|---|
| Response size: hit / miss / refusal | **43 / 34 / 95 B** | **60 / 51 / 112 B** |
| DB link | 15 lookups, 9 distinct tokens, row counts | n/a |
| Request record | | term length + 63 B |
| Timing | median **66.1 ms** (11 hits) vs **66.7 ms** (4 misses): no signal at this sample size; 16-core AMD host | |

## 6. Benchmarks (Section IX; `n = 30` timed calls after 5 warm-ups; ms)

Machine: Intel64 Family 6 Model 186, 12 logical cores, 15.6 GB RAM, Python 3.11.9;
deployment path `local-processes+postgres` (really uvicorn threads in the benchmark's own
process, PostgreSQL 16 in Docker Desktop on Windows build 26300).

| Operation | Path | Median | p95 | Caveat |
|---|---|---|---|---|
| Shamir combine (3-of-4) | in-process | **0.00970** | 0.0102 | `combine_shares` alone, not break-glass latency |
| DEK re-wrap (one DEK) | in-process | **0.0248** | 0.0320 | one DEK, not a sweep |
| Revocation (library call) | in-process | **0.239** | 0.628 | no persistence/audit/HTTP; the deployed path is a full rotation that nobody times |
| PRE re-encrypt (demo group) | in-process | **0.165** | 0.189 | 256-bit demo group; no deployed path calls it |
| Cross-facility discovery | HTTP+DB | **247** | 270 | nested signed audit call + DB write; unstable (405 then 247 ms) |
| Emergency search | HTTP+DB | **241** | 262 | same |
| Audit chain verification | DB read | **11.4** | 17.3 | chain length not recorded |

Summary sentences you can say: *all four in-process operations have medians below 0.25 ms
and p95 below 0.63 ms; the HTTP paths take ~240 to 250 ms and describe our request path, not
the cryptography.* Method: `time.perf_counter`, median and interpolated p95, **no outlier
removal or CPU pinning**. The scaling runs were **cut**.

## 7. Ciphertext expansion

Constant **16 bytes (the GCM tag)** per payload.

| Plaintext | Ciphertext | Expansion |
|---|---|---|
| 64 B | 80 B | 25 % |
| 256 B | 272 B | 6.25 % |
| 1 KiB | 1040 B | 1.5625 % |
| 4 KiB | 4112 B | 0.39 % |
| 16 KiB | 16400 B | 0.098 % |

Excluded: the 12-byte nonce, two 48-byte DEK wrappings, the compiled policy, a 66-byte share
per x, and the search index.

## 8. Protocol constants (so you never hesitate)

| Constant | Value |
|---|---|
| Shamir field | GF(p), p = 2^256 + 297 (257-bit prime), 32-byte blocks, 33-byte share element |
| Emergency key | 256-bit; **3-of-4**; holders x=1 custodian, x=2 home authority (authority-net), x=3,4 audit |
| Signature | ECDSA P-256 / SHA-256, domain-tagged and length-prefixed |
| Assertion | nonce ≥ 128 bits; lifetime ≤ **15 min**; `issued_at` ≤ **30 s** in the future; custodian default 120 s |
| Transition event | nonce ≥ 16 bytes; issue time < 15 min old (30 s skew) |
| Emergency window | deployed **4 h** (shorten-only); library default 60 s |
| Expiry monitor | checks every **0.5 s**; retry backoff cap **60 s** |
| Legal transitions | **7** (4 states) |
| Reason codes | 13 (closed enumeration) |
| Canaries | 13 (raw, hex, base64, PEM) |
| Services / ports | facility-a 8001, facility-b 8002, authority-med 8010, authority-net 8011, audit 8020, custodian 8030, portals 8000 |
| Demo password | `demo1234` (synthetic) |

## 9. "Say it exactly" sentences

- "All eleven claims hold on the evaluated commit, with 35 of 35 system-level tests passing
  and none skipped; we do not claim every claim test is shown to go red under mutation."
- "No log entry, no key holds against everyone except the audit service itself."
- "No plaintext on the wire holds under TLS only; the plain capture is the positive control."
- "Revocation is forward-only, and only the patient can revoke in this build."
- "Expiry is server-enforced, not cryptographic; a trusted timer could decline to expire, which
  we make tamper-evident."
- "The access structure is not full CP-ABE; it is not collusion-resistant and has no proof."
- "The HTTP figures are indicative only; the in-process cryptographic operations are under a
  millisecond."
