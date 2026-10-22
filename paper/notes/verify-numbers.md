# V4 verification: numbers and citations (2026-10-22)

Summary: 0 BLOCKER, 5 MINOR. 22 cite keys used, all resolve and all carry a `% verified:` url; 1 unused bib entry. 7 urls/records opened by V4.

Method: re-ran every `paper/data/make_*.py` (except `make_data.py`, which has no `main()`) with `OUT` redirected to the scratchpad and diffed. `bench.tex`, `claims.tex`, `related.tex`, `transitions.tex` and `wire.tex` are byte-identical to the committed tables. `latency.csv` and `expansion.csv` were checked by eye against `benchmark_summary.csv` and the `ciphertext_expansion` rows of `benchmark_results.csv`; they match exactly. `paper/refs.bib` entries (comments stripped) are identical to `paper/notes/refs-verified.bib` above the DROPPED block. All prose numbers in sections 00–11 were traced to their sources:
- bench medians/p95 and the < 0.25 / < 0.63 ms bounds;
- 240–250 ms, 16 B, 25 %, < 0.1 %, 48 B wrappings and the 66 B share;
- 13 canaries, 1.35 ms and 4356/4314 B;
- p53: 16 searches, 43/34/95 B, 15 lookups over 9 tokens, 60/51/112 B, +63 B and 66.1/66.7 ms;
- 35/35, 1006/2/0 and 18/43/7;
- 0.5 s, 60 s, 4 h and 16 B.

Dates are correct throughout: p53 is 2026-10-19 and pre-3-of-4; p55 is 2026-10-21 @99092d1 (the capture timestamp 1792588199 is 2026-10-21 13:09 UTC); the live run is 2026-10-21 @57a1a8c. The machine and deployment path are named in the `tab:bench` caption, and n=30 and warm-up 5 appear in the caption, in Fig. `fig:latency` and in the Method paragraph. No mean is quoted.

## Issues

[MINOR] paper/sections/08-traffic-analysis.tex:67 — The timing medians "66.1 and 66.7 ms" do not say which is hit and which is miss. They also do not give the sample size or the machine. These numbers come from a different machine (AMD64 Family 25 Model 117, 16 cores, Python 3.11.17, at `0b95f2b`+branch) than Table `tab:bench` (Intel Family 6 Model 186), so a reader will assume it is the same host. — source says: hit 0.0660853 s, miss 0.0666937 s (`p53_search_leakage_tls.json` `labelled_tls_view.median_latency_seconds_by_outcome`); 11 hits and 4 misses per run, with that environment (`p53_search_leakage.md` "How the captures were taken") — Fix: write "medians 66.1\,ms for 11 hits and 66.7\,ms for 4 misses, on a different 16-core AMD host", or drop the figures and keep "no hit/miss signal at this sample size".

[MINOR] paper/sections/02-related-work.tex:60 — "revocation flips an on-chain flag without re-encryption" is accurate. However, it omits that Romel et al. offer a separate optional re-keying workflow (Workflow 5) that re-encrypts the record so revoked recipients lose access to the new version. Our novelty includes revocation as rotation, so leaving this out reads as slightly unfair. — source says: arXiv 2511.17464v1 HTML ("Key rotation is a separate, optional step (Workflow 5)"); facts-F8#18 ("re-keying is a separate optional workflow") — Fix: append "; re-keying is a separate, optional workflow".

[MINOR] paper/sections/02-related-work.tex:18 (and 01-introduction.tex:17) — V4 could not independently confirm the hospital-emergency application in Kroll et al. WebFetch could not decode the PDF, and no PDF text tool is installed. The Yale talk page confirms the approver, the threshold of decryption authorities, the publicly verifiable auditor log and "break-glass overrides" in commercial ABAC, but not hospitals. The Yale page's title is "Flexible Cryptographic Access Control Through Accountability" (the talk). The bib title "Accountable Cryptographic Access Control" (the PDF) is not confirmed by V4. — source says: facts-F8#1 (§1.1 read from PDF text by F8) — Fix: a human should open https://www.cs.yale.edu/homes/jf/kroll-paper.pdf, check the title, the author list and §1.1, and confirm before submission. If §1.1 does not mention hospitals, cut 02:18 and the clause in 01:17.

[MINOR] paper/notes/refs-verified.bib:67 — The provenance line for `li2025accountable` cites a Crossref query for "Making Decryption Accountable Ryan" (Ryan 2017's title), not Li et al. The entry itself is correct: V4 opened https://api.crossref.org/works/10.1109/TIFS.2024.3515808 and found the title, the six authors, TIFS vol. 20, pp. 620–635, 2025. — Fix: replace that `% verified:` line with the DOI Crossref url above.

[MINOR] paper/refs.bib:303 — `blaze1998proxy` is never cited. — Fix: prune it, or cite it where the bidirectional PRE is introduced.

## URLs opened by V4

- https://arxiv.org/abs/2511.17464 and https://arxiv.org/html/2511.17464v1 (romel2025patient)
  - Metadata: title, five authors, v1 of 21 Nov 2025 and cs.CR all match refs.bib.
  - Body: EIP-712 patient-signed, time-bounded permissions; encrypted records off-chain; ECIES key wrapping; revocation sets `revoked=true` with no re-encryption; §5.8 emergency access (two co-signing physicians, 2 h, on-chain events, HSM guardian).
  - The text at 02:60–64 is supported. See MINOR on Workflow 5.
- https://arxiv.org/abs/2603.07004 and https://arxiv.org/html/2603.07004v1 (muslim2026consent)
  - Metadata: title, two authors, 7 Mar 2026 and cs.CR all match.
  - Body: XACML-based framework; pre-commit validation; emergency access logged "to ensure post-hoc accountability"; lifecycle "creation, activation, revocation, and expiration" (§1); "logical rather than cryptographic" (§7).
  - The text at 01:13 and 02:56 is supported.
- https://arxiv.org/abs/2303.04500 and https://api.crossref.org/works/10.1109/EuroSP57164.2023.00016 (cheval2023transparency)
  - Metadata: title "Automatic verification of transparency protocols", Cheval/Moreira/Ryan, EuroS&P 2023, pp. 107–121 all match.
  - Body: ProVerif, the first formal verification of transparent decryption, Merkle trees.
  - Trustees holding shares and gated on log proofs is not in the abstract. Search-indexed text of the arXiv PDF supports it: the key is split among trustees, who act if the request is in the log. Accepted.
- https://eprint.iacr.org/2023/1519 and https://api.crossref.org/works/10.1109/TIFS.2024.3515808 (li2025accountable)
  - Metadata: title, six authors, TIFS 20:620–635 and 2025 all match.
  - Abstract: formal definitions of accountable decryption plus a TEE-assisted construction. The text at 02:20 is supported. The paper does not use "PORTEX".
- https://www.cs.yale.edu/homes/jf/Kroll.html and https://www.cs.yale.edu/homes/jf/kroll-paper.pdf (kroll2018accountable)
  - The talk page is undated and confirms the approver, the threshold decryption authorities and the auditor's publicly verifiable log. That supports 02:16.
  - The PDF text could not be extracted. See the MINOR on hospital emergencies.
  - No "2018" is printed anywhere in the paper; the key name only.

## Unused refs.bib keys

- blaze1998proxy

## Round 2 (2026-10-22, after fixers)

Summary: 0 BLOCKER, 1 MINOR (still open from round 1; it is in `paper/notes/`, not in the paper). No new issues. 21 cite keys used, 21 entries in refs.bib, none unused, every one carries a `% verified:` url, and refs.bib equals refs-verified.bib minus `blaze1998proxy`. No `TODO-` key, "PORTEX", "2018", "2.27", "5/11" or "2-of-3" is printed.

What was re-checked:
- **Tables.** Re-ran all `make_*.py` with `OUT` redirected to the scratchpad. `make_data.py` was run through `write_latency`/`write_expansion`. All five tables and both data CSVs are byte-identical to the committed files.
- **What changed since round 1.** Only captions, `\textnormal` wrapping and the placement of src comments. No numeric cell changed in `bench`, `claims`, `related`, `transitions` or `wire`.
- **Related-table footnote b** ("Revocation is a transition; consent is a read-time check") is supported by facts-F1#35 and #77.
- **Section numbers.** Re-scanned every numeric token in sections, figures and secprops against the round-1 sources. New or changed prose:
  - 07:37: "claim text was written on 2026-10-07". Git confirms `e79bcd3` 2026-10-07 introduced the C3 string, and `99092d1` is 2026-10-21.
  - 07:76: "each red under some mutation" (facts-F5#46).
  - 09: "405 then 247 ms on this machine" (facts-F7#25).
  - 09: "subgroup check and one exponentiation" (facts-F7#29).
  - 01:45: eleven claims @57a1a8c.

  All match.
- **Dates** are unchanged and correct: p53 2026-10-19 pre-3-of-4; p55 2026-10-21, tree committed as `99092d1`; live run 2026-10-21 @57a1a8c.

### Round-1 issues

1. 08-traffic-analysis.tex:67 hit/miss medians — **RESOLVED**. Lines 68–70 now read "66.1 ms over 11 hits and 66.7 ms over 4 misses, on a 16-core AMD host, not that of Table bench", tagged facts-F6#92. This matches `p53_search_leakage_tls.json` (0.06609 / 0.06669 s) and the environment in `p53_search_leakage.md`.
2. 02-related-work.tex:60 Romel re-keying — **RESOLVED**. It now says "re-keying is a separate, optional workflow".
3. Kroll hospital emergencies and title — **RESOLVED**. V4 extracted the PDF text with a zlib stream decoder (scratchpad `pdftxt.py`, no install).
   - Title: "Accountable Cryptographic Access Control".
   - Authors: Kroll, Zimmerman, Wu, Nikolaenko, Felten, Boneh. Undated.
   - The "Hospital patient records" paragraph supports the text at 01:17 and 02:18. It describes exceptional access "for health emergencies" when "an unpredictable set of hospital staff" needs records, with an audit record so internal reviewers can check for abuse.
4. refs-verified.bib:67 li2025 provenance url — **STILL OPEN** [MINOR] paper/notes/refs-verified.bib:67. The `% verified:` line still points to the Crossref query "Making+Decryption+Accountable+Ryan". The paper entry is correct (V4 opened https://api.crossref.org/works/10.1109/TIFS.2024.3515808). Fix: replace that url with the DOI Crossref url. This has no effect on the paper.
5. Unused `blaze1998proxy` — **RESOLVED** (pruned from refs.bib).

### Unused refs.bib keys (round 2)

None.
