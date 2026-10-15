# P5-3 search leakage: measured from real captures

Source data: `p53_search_leakage.json` (plain) and `p53_search_leakage_tls.json`
(TLS), written by `python -m wire.analyze_search_leakage`. Method and
decisions: ADR-0070. Every number below comes from those files; nothing comes
from the application's own logs.

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
- Environment: Windows 11 (10.0.26300), Intel64 Family 6 Model 186, Python
  3.11.9, TShark 4.6.9, Postgres 16 (throwaway container), code at `532e57a`
  plus this change.
  The plain and TLS runs are separate runs, so their tokens differ: each run
  generates fresh keys.

## What an observer learns

The observer is on loopback, seeing the HTTP links (clinician → facility)
and the facility's link to Postgres.

| Leak | Plain HTTP profile | TLS profile |
|---|---|---|
| Query term | **In the clear**: 16/16 search bodies readable | Hidden on the HTTP link |
| Query length | Exact | **Exact**: request body record = body + 17 B (70 B for 7-letter terms, 71/72/73 B for 8/9/10) |
| Query volume | 16 searches | 15 search exchanges (the refused one makes no lookup) |
| Frequency (per key epoch) | `cardiac` 5, `aspirin` 2, others 1; again `cardiac` 2 after rotation | **Same histogram** from the database link: tokens seen 5, 2, 2, 1, 1, 1, 1, 1, 1 times |
| Search token | Database link: 15 lookups, 9 distinct tokens | **Same**: the database link is not TLS |
| Hit or miss | Response body 43 B (1 result) vs 34 B (0 results); refused 95 B | Response body record **60 B vs 51 B**; the database link also shows `SELECT 1` vs `SELECT 0` for all 15 |
| Timing | Every search timestamped; median latency hit 0.788 s, miss 0.799 s | Median latency hit 0.065 s, miss 0.076 s |

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
is bounded by the emergency window, not removed.

## What this means for the paper

1. **Deterministic tokens leak search frequency within a session, by design.**
   ADR-0027 says so; the capture measures it. Expiry ends the linkability:
   tokens from different sessions do not match.
2. **TLS on the federation's HTTP links is not enough.** The facility↔Postgres
   link is plaintext in both profiles, so the token, its frequency and the
   result count reach any observer of that link. Even on the HTTP link, TLS
   leaves response size (hit vs miss) and request size (term length) exactly
   measurable. Closing this needs Postgres TLS (`sslmode=verify-full`) and
   padding of search requests and responses. Neither is implemented.
3. **Misses still leak.** A term that matches nothing still produces a
   distinct, repeatable token on the database link (`pneumonia`, `warfarin`).
   An observer learns that it was searched and that it missed.
4. **Timing shows no hit/miss signal at this sample size** (4 misses, 11 hits;
   medians within 11 ms over TLS). Latency is dominated by the per-search audit
   append (log-before-release), not by the index lookup. One TLS outlier
   (0.617 s) is the first search after the second break-glass. The plain run's
   latencies (~0.8 s) are about 10× the TLS run's on the same machine. That is
   a property of this Windows loopback run, not of the protocol; do not quote
   it as overhead.

## Limitations of this measurement

- One record, so `record_count` is only ever 0 or 1. Tokens are per record
  (per emergency key), so a multi-record result needs several records under
  the same key, which this design does not have.
- 16 searches is enough to show each leak, not to estimate a timing
  distribution.
- TLS exchanges are paired to lookups by time. That is valid because the
  workload searches one at a time; concurrent load could mispair them.
