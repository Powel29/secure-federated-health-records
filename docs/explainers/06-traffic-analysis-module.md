# 6. The required course module: Traffic Analysis (Module 7)

*Paper: Section VIII (Traffic Analysis) and its wire-checks table. Decisions:
ADR-0042 (capture harness), ADR-0045 (wire-claim checks), ADR-0047/0071 (TLS),
ADR-0073 (claim 1 scoped to TLS).*

**One-paragraph version.** The lab requires us to *implement and demonstrate* one
security module. We chose Wireshark/PyShark traffic analysis because it attacks our
own claims from the outside: an observer who does not trust our code watches the
wire and checks what leaks. It ships as **PyShark analyser code that exits
non-zero when a wire property fails**, not as screenshots. **It has been run on
real captures** (plain and TLS, captured 2026-10-21) and every check passes.

## Rules we follow

- Capture **only our own synthetic federation**, on **allowlisted loopback or
  Docker-bridge interfaces**. Any other interface is refused (`CLAUDE.md`,
  `PROJECT.md` §4A). Never campus, shared or third-party networks.
- The capture is filtered to the **six federation ports plus Postgres**.
- **One scenario is captured over plain HTTP and again under TLS**, the Postgres
  link included.

## How the analyser works

It **reassembles TCP streams** and searches for **13 canaries** (record plaintext,
DEK, emergency key, shares, attribute keys, a signing key) as **raw bytes, hex,
base64 and PEM**. **A lost segment fails the check** (so a missing packet can never
look like a clean result).

## Why we capture *both* plain and TLS (this changed; read carefully)

An older version of this explainer said "plain HTTP shows our application-layer
encryption protects the data". **The paper's result is different, and more honest:**
under **plain** HTTP the facility encrypts and decrypts server-side, so **record
plaintext, the emergency key and four attribute keys cross in the clear**. That is
why the claim is stated this way:

> **"No plaintext on the wire" holds under TLS only** (limitation 11, ADR-0073).

The plain capture is the **positive control**: it proves the detector fires. **A
clean TLS result is not trusted unless the control fires.** Even on the plain wire,
**no share and no signing key appears**, because shares travel sealed. The DEK
canary had no plain hit either (the design caveat lists DEKs; our capture found
none, but found the emergency key at ingest).

Caveat: the TLS is **self-signed and server-only, with no version or cipher suite
pinned**.

## The results (paper wire-checks table; captured 2026-10-21 at commit `99092d1`,
the capture/analyser/service code is unchanged in the evaluated commit `57a1a8c`)

| # | Property | Plain capture | TLS capture | Result |
|---|---|---|---|---|
| 0 | Preconditions | 16 endpoints seen | TLS records only | pass |
| 1 | No plaintext | **6 of 13 canaries hit (control fired)** | **0 of 13 canaries hit** | pass |
| 2 | Commit before release | **COMMIT 1.35 ms before response** | n/a (plain only) | pass |
| 3 | Search leakage | 1 search, 1 term in clear, 43 B response | n/a (plain only) | pass* |
| 4 | Break-glass as metadata | URI visible; 4314 B request | **4356 B burst; 0 content hits** | pass |

*Check 3 is a **measurement**: it fails only if no search traffic is captured.

## What each check proves

1. **No plaintext on the wire** (TLS only; plain = positive control).
2. **Commit before release.** The analyser matches the audit service's **Postgres
   INSERT and `COMMIT` acknowledgement** to the `/breakglass/release` response, in
   which the **sealed audit shares must first appear** (it keys on share 3; share 4
   travels in the same response and is not timed separately). The COMMIT reaches
   the wire **1.35 ms before** the response. This needs an **unencrypted database
   link**, so it runs on the **plain capture only**. This is the empirical
   counterpart of the commit-then-release rule (file 3).
3. **Search leakage, measured.**
4. **Break-glass is metadata only.** A size-only observer picks the **largest burst
   to the facility** as the unlock (rule validated on the plain capture). Under TLS
   it sees a **4356-byte unlock burst** and no share, emergency key or DEK: it
   learns **that, where and when** a break-glass happened, and its size.

## Search leakage in numbers

The wire table measured **one** search. The multi-search figures come from **two
runs dated 2026-10-19, before the 3-of-4 change** (the search module is unchanged),
each with **16 searches on one record**, one refused after expiry. The paper dates
them rather than re-running; do the same.

- **Plain wire:** all terms visible; response size separates **hit, miss and
  refusal (43, 34, 95 B)**; the database link shows **15 lookups over 9 distinct
  tokens with row counts**.
- **Deterministic tokens** link repeated searches within a session (the
  search-pattern leakage of deterministic searchable encryption); but the **three
  terms searched across expiry got new tokens**.
- **Under TLS:** no URI, term or token is visible, yet response records still
  separate hit, miss and refusal (**60, 51, 112 B**) and each request record is the
  **term length plus 63 B**.
- **Timing:** no hit/miss signal at this sample size (medians **66.1 ms over 11
  hits and 66.7 ms over 4 misses**, on a 16-core AMD host, *not* the benchmark
  machine). **There is no padding.**

## How to run it

```bash
python -m wire.tls                                   # local certs
python -m wire.capture --mode plain --out wire/captures/plain.pcap
CAPTURE_TLS=true TLS_ENABLED=true python -m wire.capture --mode tls --out wire/captures/tls.pcap
python -m wire.analyze_traffic --captures wire/captures
```

Needs `tshark`/`dumpcap` on `PATH` (Wireshark with Npcap on Windows; pass the Npcap
loopback adapter, `tshark -D` lists it). Set `PYTHONUTF8=1` on Windows. Two tests in
`tests/wire/test_capture.py` test the *missing-dumpcap* path and skip by design when
the tool is present. Checks are explicit results, not `assert`, so `python -O`
cannot strip them.

## If asked

*"Why not another module?"* The others (WiFi cracking, USB or Windows forensics,
reverse engineering) are unrelated to an encrypted health-record system. Traffic
analysis is the only one that tests *our* design. Module 4 (PCAP to SQLite) was
dropped: pandas, already in our benchmark harness, does the same job.

*"Is this a real attack?"* It is an **observer model**: what an on-path eavesdropper
would learn. The threat model has **no** on-path attacker; "no plaintext on the
wire" is a goal of the TLS profile only.

*"Why a database COMMIT on the wire?"* The audit service talks to Postgres over
TCP, so the COMMIT is observable and orders the events.

*"Why canaries?"* Detection is mechanical and covers every encoding, not eyeballing.
