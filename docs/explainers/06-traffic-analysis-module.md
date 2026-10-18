# 6. The required course module: Traffic Analysis (Module 7)

**One-paragraph version.** The lab requires us to *implement and demonstrate*
one security module. We chose Wireshark/PyShark traffic analysis because it
attacks our own claims from the outside: an observer who does not trust our code
watches the wire and checks what leaks. It ships as code that **asserts**
properties automatically, not as screenshots.

## Why capture *plain* HTTP on purpose

If we only captured TLS traffic we would learn nothing: of course encrypted
traffic looks encrypted. We run the federation **without** TLS in the main
profile so that, if the capture shows no patient data, the credit goes to our
**application-layer encryption**. A second TLS profile shows defence in depth.

| Profile | Transport | Purpose |
|---|---|---|
| `capture-plain` | plain HTTP between services | the evidence |
| `capture-tls` | TLS | defence in depth |

The TLS profile uses **verified** certificates (ADR-0047). `python -m wire.tls`
writes one key directory per service plus a shared trust bundle
(`wire/certs/trust/ca-bundle.crt`); every federation client trusts that bundle,
and no `verify=false` is used anywhere. In Compose each container mounts only
its own key. Turn it on with `TLS_ENABLED=true`.

## The four things the analysers must prove

1. **No plaintext on the wire.** No patient data, data keys, attribute keys or
   shares in the clear during reads, revocation or break-glass.
2. **Commit before release.** The audit service's share never appears on the
   wire before the response carrying the new chain head. Our headline claim,
   checked by an observer.
3. **Search leakage, measured.** Access pattern, query volume, response size,
   quantified. Finding leakage is a result, not a failure.
4. **Break-glass is visible as metadata, not as content.** An observer sees that
   an emergency happened but cannot recover the emergency key.

## Rules we follow

Capture **only our own synthetic federation**, on loopback or the Docker bridge.
Never campus, shared or third-party networks, even for practice
(`CLAUDE.md`, `PROJECT.md` §4A).

## How to run it (from the README)

```bash
python -m wire.tls                                   # local certs
python -m wire.capture --mode plain --out wire/captures/plain.pcap
python -m wire.analyze_traffic --captures wire/captures
```

On Windows pass the Npcap loopback adapter (`tshark -D` to list it). The
capture harness (P4-6, ADR-0042) and the analyser that asserts all four claims
(P5-5, ADR-0045, negative tests in CI) exist. The run over real captures of
both profiles is the remaining P5-5 evidence, so describe it as built-but-pending
unless you have run it yourself.

## If asked "why not another module?"

The others (WiFi cracking, USB or Windows forensics, reverse engineering) are
unrelated to an encrypted health-record system. Traffic analysis is the only
one that tests *our* design. Module 4 (PCAP to SQLite) was dropped because
pandas, already used by our benchmark harness, does the same job.
