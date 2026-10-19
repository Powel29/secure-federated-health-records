# P5-3 search leakage: measured from real captures

Source data: `p53_search_leakage.json` (plain profile) and
`p53_search_leakage_tls.json` (TLS profile, store link encrypted), written by
`python -m wire.analyze_search_leakage`. Method and decisions: ADR-0070 (the
workload and observer views) and ADR-0071 (TLS on the store link). Every
number below comes from those files; nothing comes from the application's
own logs. The "TLS before ADR-0071" column is from the same file at commit
`aae1c3b`, captured before the store link was encrypted.

## How the captures were taken

- Workload: `python -m wire.capture --mode {plain,tls} --search-workload` (Postgres on 55432,
  taken from `DATABASE_URL`),
  running `deploy.run_scenario --search-workload` against `deploy.run_local`
  with `SEED_DATA=false`.
  - First session: 1 scenario search and 10 workload searches, 0.5 s apart:
    `cardiac aspirin cardiac pneumonia infarction cardiac fracture aspirin cardiac warfarin`.
    Indexed terms are `cardiac`, `infarction` and `aspirin`; the rest miss.
  - Expiry and forced rotation (ADR-0069), then 1 search, which was refused (403).
  - Second break-glass (through the custodian), then 4 searches:
    `cardiac aspirin fracture cardiac`.
- Capture: dumpcap on `\Device\NPF_Loopback`, BPF pinned to the six
  federation ports plus Postgres (55432). Only our own synthetic federation
  was captured.
- TLS profile with ADR-0071: the throwaway store was started through
  `deploy/store-entrypoint.sh` (TLS 1.3 only, `hostnossl … reject`), and the
  analysis ran with `--searches wire/captures/tls-search.searches.json` to
  label the exchanges. The labels only say which exchange was which search;
  every size and time comes off the wire.
- Environment: Windows 11 (10.0.26300), AMD64 Family 25 Model 117, 16
  cores, Python 3.11.17, TShark 4.6.9, Postgres 16 (throwaway container).
  Both runs re-recorded 2026-10-19 at `0b95f2b` plus branch
  `proposal/review-worth-doing-f31-f10` (review E4). Every run generates fresh
  keys, so tokens differ between runs.

## What an observer learns

The observer is on loopback, seeing the HTTP links (clinician → facility)
and the facility's link to Postgres.

| Leak | Plain profile | TLS before ADR-0071 | TLS with ADR-0071 |
|---|---|---|---|
| Query term | **In the clear**: 16/16 bodies readable | Hidden | Hidden |
| Query length | Exact | **Exact** (request body record = term + 63 B) | **Exact**: same; 15/15 requests are term length + 63 B |
| Store link | Plaintext | **Plaintext** | **TLS**: 4/4 connections, 0 readable lookups |
| Search token | 15 lookups, 9 distinct tokens | Same, from the store link | **Hidden** |
| Frequency (per key epoch) | `cardiac` 5, `aspirin` 2, others 1; `cardiac` 2 after rotation | **Same histogram** from the store link (5, 2, 2, 1, …) | **Only per term length**: request sizes 70 B ×9, 71 B ×3, 72 B ×1, 73 B ×1 |
| Hit or miss | Response body 43 B vs 34 B; refused 95 B | Response body record 60 B vs 51 B; the store link also shows `SELECT 1`/`SELECT 0` | Response body record **60 B vs 51 B; refused 112 B** (fully separable) |
| Timing | Median latency hit 0.102 s, miss 0.098 s | Median hit 0.065 s, miss 0.076 s | Median hit 0.066 s, miss 0.067 s, refused 0.030 s |

### Re-keying at expiry (ADR-0069), measured

In the plain capture each token can be tied to its term. The refused search
splits the run into two key epochs:

| Term | Token, epoch 0 | Token, epoch 1 |
|---|---|---|
| cardiac | `a7e370618710` (×5) | `0f3165b9ab7c` (×2) |
| aspirin | `597ab9176327` (×2) | `045233096720` |
| fracture (miss) | `35a2d21c508f` | `eab26bb6cca9` |

All 3 terms searched in both epochs got a new token after rotation
(`terms_rekeyed_across_epochs`), and within an epoch each term kept one token
(`same_term_same_token_within_epoch: true`). No token was shared by two terms.
So an observer can link repeated searches **within** one emergency
session, but not across sessions. The deterministic-token leakage of ADR-0027
is bounded by the emergency window, not removed. With ADR-0071 the TLS
profile no longer shows tokens at all, so this linkage is visible only in
the plain profile or to someone who can read the store.

## What this means for the paper

1. **Deterministic tokens leak search frequency within a session, by design.**
   ADR-0027 says so; the capture measures it. Expiry ends the linkability:
   tokens from different sessions do not match.
2. **TLS has to cover the store link, or it hides little.** Before ADR-0071
   the facility↔Postgres link was plaintext in the TLS profile, so tokens,
   their frequency and row counts reached any observer of it. With
   `verify-full` on that link (ADR-0071), the token and the row count are
   gone from the wire, and frequency is visible only by term length.
3. **Sizes are the residual leak, and they are exact.** Over TLS the response
   body record still separates hit (60 B), miss (51 B) and refused (112 B)
   every time. The request body record is always the term's length + 63 B,
   so the observer learns each query's length and how often each length is
   searched (`cardiac` and `aspirin` share 70 B). Closing this needs fixed-size
   padding of search requests and responses, which is not implemented.
4. **Misses still leak.** A term that matches nothing is still a separate,
   sized exchange (51 B), and in the plain profile a distinct, repeatable
   token on the store link (`pneumonia`, `warfarin`).
5. **Timing shows no hit/miss signal at this sample size** (4 misses, 11 hits
   per run). On the 2026-10-19 runs the medians are within a few
   milliseconds (plain hit 102 vs miss 98 ms; TLS hit 66 vs miss 67 ms), and
   the pre-ADR-0071 TLS run had the opposite sign (65 vs 76 ms), which is
   what noise looks like. Latency is dominated by the per-search audit append
   (log-before-release), not by the index lookup. A refused search answers
   faster (30 ms over TLS) because it stops before the lookup and the append;
   its response size already gives it away. The earlier plain run's ~0.8 s
   latencies did not recur on this machine, so they were a property of that
   Windows loopback run, not of the protocol; do not quote any of these as
   overhead. Latency is measured last record to last record, so TLS 1.3
   session tickets ahead of a response no longer inflate it.

## Limitations of this measurement

- One record, so `record_count` is only ever 0 or 1. Tokens are per record
  (per emergency key), so a multi-record result needs several records under
  the same key, which this design does not have.
- 16 searches is enough to show each leak, not to estimate a timing
  distribution.
- TLS exchanges are paired by time, to token lookups (store link readable)
  or to the workload's manifest (store link encrypted). That is valid
  because the workload searches one at a time; concurrent load could mispair
  them.
- The labelled view uses the client's clock against the capture's. On
  loopback both are the same host clock; every request landed 1–22 ms after
  its `sent_at`.
