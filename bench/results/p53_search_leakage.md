# P5-3 search leakage: measured from real captures

Source data: `p53_search_leakage.json` (plain profile) and
`p53_search_leakage_tls.json` (TLS profile, store link encrypted), written by
`python -m wire.analyze_search_leakage`. Method and decisions: ADR-0070 (the
workload and observer views) and ADR-0071 (TLS on the store link). Every
number below comes from those files; nothing comes from the application's
own logs. The "TLS before ADR-0071" column is from the same file at commit
`aae1c3b`, captured before the store link was encrypted.

## How the captures were taken

- Workload: `python -m wire.capture --mode {plain,tls} --search-workload --db-port 55433`,
  running `deploy.run_scenario --search-workload` against `deploy.run_local`
  with `SEED_DATA=false`.
  - First session: 1 scenario search and 10 workload searches, 0.5 s apart:
    `cardiac aspirin cardiac pneumonia infarction cardiac fracture aspirin cardiac warfarin`.
    Indexed terms are `cardiac`, `infarction` and `aspirin`; the rest miss.
  - Expiry and forced rotation (ADR-0069), then 1 search, which was refused (403).
  - Second break-glass (through the custodian), then 4 searches:
    `cardiac aspirin fracture cardiac`.
- Capture: dumpcap on `\Device\NPF_Loopback`, BPF pinned to the six
  federation ports plus Postgres (55433). Only our own synthetic federation
  was captured.
- TLS profile with ADR-0071: the throwaway store was started through
  `deploy/store-entrypoint.sh` (TLS 1.3 only, `hostnossl … reject`), and the
  analysis ran with `--searches wire/captures/tls-search.searches.json` to
  label the exchanges. The labels only say which exchange was which search;
  every size and time comes off the wire.
- Environment: Windows 11 (10.0.26300), Intel64 Family 6 Model 186, Python
  3.11.9, TShark 4.6.9, Postgres 16 (throwaway container). Plain run at
  `532e57a` plus ADR-0070; TLS run at `aae1c3b` plus ADR-0071. Every run
  generates fresh keys, so tokens differ between runs.

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
| Timing | Median latency hit 0.788 s, miss 0.799 s | Median hit 0.065 s, miss 0.076 s | Median hit 0.072 s, miss 0.054 s, refused 0.070 s |

### Re-keying at expiry (ADR-0069), measured

In the plain capture each token can be tied to its term. The refused search
splits the run into two key epochs:

| Term | Token, epoch 0 | Token, epoch 1 |
|---|---|---|
| cardiac | `2185ec97c241` (×5) | `63a445dcf12a` (×2) |
| aspirin | `ef5dc5f7c1f2` (×2) | `a8307f24a10f` |
| fracture (miss) | `9b9b8964d3dd` | `95dd748e3e48` |

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
5. **Timing shows no hit/miss signal at this sample size** (4 misses, 10-11 hits
   per TLS run). The direction of the median difference flips between the two
   TLS runs (hit 65 vs miss 76 ms, then 72 vs 54 ms), which is what noise
   looks like. Latency is dominated by the per-search audit append
   (log-before-release), not by the index lookup. The plain run's latencies
   (~0.8 s) are about 10× the TLS runs' on the same machine. That is a
   property of this Windows loopback run, not of the protocol; do not quote it
   as overhead. The 0.617 s outlier in the pre-ADR-0071 run came from timing
   from a burst's first record, where TLS 1.3 session tickets can sit ahead
   of the response. Latency is now measured last record to last record.

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
