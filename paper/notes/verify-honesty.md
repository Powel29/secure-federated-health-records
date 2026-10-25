# V3 honesty and novelty verification

Summary: 1 BLOCKER, 5 MINOR. Checklist: 10 PASS, 1 FAIL (item 8, triggered only by the literal "two-of-three" rule).

Checked against PROJECT.md §4/§5/§6 (§5 has 13 caveats), WRITER-RULES.md, ieee-paper SKILL.md, ADR-0088 (Status: Proposed), the review's status note, facts-live.md, facts-F8.md, and every file in paper/sections, paper/tables and paper/figures.

## Checklist

1. PASS. All 13 §5 caveats are in Section X (10-limitations.tex), numbered (1)–(13) in §5's order. Their meaning is preserved, and the 3-of-4 corrections ("shares 3 and 4") are applied. The cut scalability runs are stated (10-limitations.tex:76-77). One small drift on item 11 is noted below (MINOR).
2. PASS. The abstract (00-abstract.tex:13) names: revocation forward-only; expiry server-enforced, not cryptographic; not full CP-ABE (not collusion-resistant); audit service trusted (no proofs of presence or extension); audit service a single point of availability, with the home authority's share replacing only a lost custodian share; "no plaintext on the wire" under TLS only. It also says "simulated federation with synthetic data" (00-abstract.tex:11).
3. PASS. Nothing in §6 is claimed. The paper says there is no ML layer, no FHIR/HL7 or HIE (04:62, 10:78), and no real CP-ABE (future work). The HSM is simulated (03:37, 10:11), there is no production deployment, and the data is synthetic.
4. PASS. tables/claims.tex shows all 11 claims as "holds", with 35 system-level tests and the caption "2026-10-21 at 57a1a8c". This matches facts-live#1-13. The statements are verbatim. The suite totals (1006/2/0) match facts-live#14. Nothing is upgraded or softened.
5. PASS. ADR-0089, 0079, 0058, 0081, 0084 and 0050 are all marked "Proposed" or "this build chooses". ADR-0014, 0016, 0030 and 0043 are Accepted. ADR-0088 (Proposed) is not cited as agreed.
6. PASS. Kroll et al.'s hospital-emergency application is acknowledged (01:17, 02:18). 2511.17464's two-physician break-glass is acknowledged (02:117-119). Transparent decryption is credited as "the primitive we instantiate" (02:77; 00:7; 11:4). The paper says our log is weaker (01:50, 02:79, 10:68-74). Kroll is printed with no year.
7. PASS. There is no "first", "novel" or "unlike prior work" claim. The contribution is worded as "the combination, implemented" (01:30, 11:9). The paper says "Not every transition rotates keys" (05:38) and that Grant is a baseline with no wrapping (05:19-21).
8. FAIL. 11-conclusion.tex:21 uses "any-two-of-three", which trips the literal rule (see the BLOCKER below). The paper has no stale "bypass", "5/11", unchecked-assertion or expiry-shares finding.
9. PASS. romel2025patient (2511.17464) is cited for signed, time-bounded grants, and its revocation is described as flipping a flag.
10. PASS. tables/secprops.tex marks the policy tree and the PRE "Not proven" (and the KEM and Shamir code too). 07:89-94 says they have no proof. There is no IND-CPA, unidirectionality or collusion-resistance claim. The paper says explicitly that the PRE is bidirectional and the tree is not collusion-resistant.
11. PASS. The federation is called simulated, on one machine, in the abstract, 01:28, 04:58-62, the Fig. 1 caption and 10:78. 09:95-98 discloses that the benchmark services ran in threads.

## Issues

[BLOCKER] paper/sections/11-conclusion.tex:21 — "a home authority that also logs, giving a real any-two-of-three fallback" uses 2-of-3 wording, which the verification rule forbids outright. In substance it accurately paraphrases the future work in §5 item 8, but a reader or reviewer scanning for the stale 2-of-3 design will take it as the old split. — Fix: replace it with "a home authority that also logs, so that break-glass can proceed without the audit service".

[MINOR] paper/sections/10-limitations.tex:60-64 — On item 11, §5 (and facts-F6#6) say "record plaintext, DEKs and attribute keys cross". The paper drops DEKs and substitutes "(at ingest) the emergency key". This is evidence-based (facts-F6#37: the run had no DEK hit), but it reads as narrower than the caveat. — Fix: "On the plain profile, record plaintext and attribute keys cross in the clear, as does the emergency key at ingest, because the facility encrypts and decrypts server-side (the DEK canary did not appear in our capture, but the profile does not protect it); ..."

[MINOR] paper/sections/08-traffic-analysis.tex:33 — "inside which the sealed share~3 must first appear" brings back "share 3" on its own, the wording from the 2-of-3 era. — Fix: "inside which the sealed audit shares must first appear (the analyser keys on share~3; share~4 travels in the same response and is not timed separately)", and delete the now-redundant clause at line 38.

[MINOR] paper/sections/02-related-work.tex:115 — 2511.17464's revocation is described as flipping an on-chain flag "without re-encryption", but facts-F8#18 says re-keying exists as a separate optional workflow. Leaving that out is slightly unfair to the rival. — Fix: "revocation flips an on-chain flag and does not itself re-encrypt; re-keying is a separate, optional workflow."

[MINOR] paper/sections/02-related-work.tex:95 — "None of these is described as making key release conditional on a committed log entry" sits awkwardly with tables/related.tex:35, which marks Scafuro LG as partial (detectable one-time break). — Fix: "None of these gates key release on a committed log entry (Scafuro's scheme makes the break detectable, not log-gated), and ..."

[MINOR] paper/sections/02-related-work.tex:77 — "our logger is a mandatory holder of a per-record emergency key" overstates: the logger holds two of four shares, not the key. — Fix: "our logger holds two of the four shares of each record's emergency key, so every unlock needs it, checks a signed Emergency Assertion before it commits, ..."

## Round 2

Summary: 1 BLOCKER, 0 MINOR (new). All 6 round-1 issues are RESOLVED. Checklist: 10 PASS, 1 FAIL (item 6).

### Round-1 issues

- [BLOCKER] 11-conclusion.tex:21 "any-two-of-three": RESOLVED. It now reads "a home authority that also logs, so that break-glass can proceed without the audit service" (11:130-131). No 2-of-3 wording remains anywhere in sections, tables or figures.
- [MINOR] 10-limitations.tex item 11 dropped DEKs: RESOLVED. 10:79-83 now says the design caveat lists DEKs, that the plain capture found none, and that it found the emergency key at ingest.
- [MINOR] 08-traffic-analysis.tex:33 "share~3" alone: RESOLVED. It now says "sealed audit shares", and explains that the analyser keys on share 3 and that share 4 travels in the same response.
- [MINOR] 02-related-work.tex:115 2511.17464 re-keying omitted: RESOLVED (02:60, "re-keying is a separate, optional workflow").
- [MINOR] 02-related-work.tex:95 vs Scafuro's LG: RESOLVED (02:40, "Scafuro's break is detectable, not log-gated").
- [MINOR] 02-related-work.tex:77 "holder of a per-record emergency key": RESOLVED (02:22, "holds two of the four shares").

### Checklist (round 2)

1. PASS. All 13 §5 items are present, in order. Tagging now goes through facts-F9#1-13, which follow §5 item by item. Nothing is watered down, the item-11 correction is now explicit, and the cut scalability runs are stated (10:97-98).
2. PASS. Abstract line 13 is unchanged and still names all six limitations. "Simulated federation with synthetic data" is still at line 11.
3. PASS.
4. PASS. tables/claims.tex is unchanged (2026-10-21 @57a1a8c, 11 holds, 35 system tests).
5. PASS. No new ADR is cited. Proposed ADRs are still labelled.
6. FAIL. See the new BLOCKER: after its "often" was removed, the abstract's opening sentence makes a universal claim that 02:62-64 contradicts. Kroll et al., the 2511.17464 break-glass and transparent-decryption credit are otherwise intact.
7. PASS. The consent reframing narrows the claim honestly. Intro contribution 1 and the conclusion now say revocation, break-glass and expiry are transitions, and consent is a signed read-time check, not a transition (consistent with facts-F1#77, 05:19-21). The "This work" LC cell is now partial, with footnote b. The contribution is still "the combination, implemented" (01:30, 11:121-122). There is no "first" or "novel" claim, no "every transition rotates", and no claim that Grant wraps a key.
8. PASS. There is no 2-of-3, bypass, "5/11", unchecked-assertion or expiry-shares wording.
9. PASS.
10. PASS. secprops is unchanged: the policy tree and the PRE are "Not proven".
11. PASS.

### New issues

[BLOCKER] paper/sections/00-abstract.tex:3 — "In the health-record systems we compare, ... emergency overrides are logged after the fact." Round 1 had "often log ... only after the fact". With "often" removed, this is a universal claim about rivals, and our own related work refutes it. 2511.17464 emits its co-signed emergency grant as an on-chain event at request time, before access (02:62-64, facts-F8#18). Kroll et al. require log certification before access and name hospital emergencies (02:16-18). The sentence also says consent and break-glass are "separate mechanisms" in rivals, while our own consent is now a separate read-time check, which weakens the contrast. — Fix: "In the health-record systems we compare, emergency overrides are logged after the fact or, where logged first, the log does not gate key release, and revocation is not tied to the same key lifecycle as break-glass."

## Round 3

Summary: 0 BLOCKER, 0 MINOR. Re-checked items 2, 6, 7 and 8, all PASS, over 00-abstract.tex, 01-introduction.tex, 02-related-work.tex, 11-conclusion.tex and tables/related.tex.

### Round-2 issue

- [BLOCKER] 00-abstract.tex:3, the universal "logged after the fact" claim: RESOLVED.
  - The new gap statement (00:3) says that, in the works compared, the log-gated schemes carry no patient revocation lifecycle, and that the health-record break-glass schemes do not gate key release on a committed log entry.
  - This matches the table. Kroll, Ryan, Cheval, Larch and Li 2025 have LG yes and LC no. Romel, de Oliveira, Li 2013, LiBAC and Muslim have LG no or ?.
  - It also matches facts-F8#23. It no longer contradicts 2511.17464's on-chain grant event or Kroll's certify-before-access.
  - The intro (01:9-14) makes the same scoped claim.

### Checklist (round 3, items 2/6/7/8)

2. PASS. Abstract line 13 is unchanged and names all six limitations. "Simulated federation with synthetic data" is still in the abstract (line 11).
6. PASS. Kroll et al.'s hospital-emergency application is acknowledged in 01:7 and 02:18. 2511.17464's two-physician break-glass is acknowledged in 02 (final paragraph), along with its optional re-keying. Transparent decryption is credited as "the primitive we instantiate" (02, and the abstract's "Following transparent decryption"; 11:7-8). The weaker-log admission is kept (01: "We are weaker…", 02: "Our log is weaker than all of these").
7. PASS.
   - The contribution is worded as "the combination, implemented, and not any of its parts" (01) and "Log-gated decryption itself is prior art; our contribution is the combination" (11).
   - There is no "first to", "novel" or "every transition rotates" claim, and no claim that Grant wraps a key.
   - The consent wording ("a patient-signed grant checked at read time when one is presented, separate from the lifecycle state") matches facts-F1#77-78, including that the check is optional. The "This work" LC cell is partial, with footnote b.
8. PASS. 00, 01, 02, 11 and related.tex contain no 2-of-3, two-of-three, bare "share 3", bypass or "5/11" wording.
