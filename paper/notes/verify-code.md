# V2 code-truth verification (re-derived from src/, then diffed)

**Summary: 2 BLOCKER, 11 MINOR.** Checked: sections 03, 04, 05, 06, 07, 09, 10; figures states, breakglass-sequence, gate-chain, components (inline in 04); tables transitions, secprops. Most numbers, field names and step orders match the code. The two blockers are a transition the code can emit that the table, the figure and the text leave out, and a check that the paper describes wrongly.

## Values re-derived from the code

| Item | Code value | path:line |
|---|---|---|
| States | GRANTED, REVOKED, EMERGENCY_OPEN, EXPIRED | src/contracts/enums.py:73-79 |
| Legal pairs (7) | G->R, G->EO, R->G, R->EO, EO->X, X->G, X->R | src/lifecycle/state_machine.py:52-62 |
| Reason code required | only on G->EO and R->EO | state_machine.py:64-69,127-130 |
| Illegal handling | validate before sign; IllegalTransitionError; apply = verify sig -> legality -> from_state==current -> consume id | state_machine.py:123-126,167,343-350 |
| Signed bytes | encode_fields("ehr/transition-event/v1", 8 fields), 4-byte BE length prefix on the domain and on each field | state_machine.py:39,90-101; crypto_core/encoding.py:18-50 |
| Signers | G->R: patient (custodian); ->EO: clinician (custodian); EO->X, X->G/R: timer key, fresh per facility process | custodian/__init__.py:100-140; deploy/asgi/facility.py:147-150; expiry.py:646-683 |
| **X->R also patient-signable** | custodian signs `state -> REVOKED` from whatever state the facility reports; the facility accepts any from_state equal to the stored state | custodian_service.py:1324-1343; hospital.py:1126-1144 |
| Rotation contents | new DEK + new policy id; new 32 B root secret, baseline gen+1; new K_E split 3-of-4, emergency gen+1; search tokens re-derived; terms re-sealed | lifecycle/rotation.py:238-290 |
| Who rotates | revoke (hospital.py:1158-1190) and expiry (api/rotation.py:107-148); break-glass open does not rotate | gate.py:588-632 |
| Shamir | p = 2^256+297; 32 B blocks of (4 B length prefix + secret, zero-padded); 33 B per block per share, so a 32 B K_E gives 66 B shares | shamir/finite_field.py:345-347; shamir/split.py:472-496 |
| Split / holders | k=3, n=4; x=1 custodian, x=2 home authority, x=3,4 audit | breakglass/emergency_key.py:28-37 |
| Gate checks | verify the signed event (open path only), then x in 1..P-1, at least 3 distinct x, combine first 3, AES-GCM unwrap, KEM | gate.py:537-546,599-632 |
| Assertion fields | assertion_id, patient_id, clinician_id, facility_id, reason_code, issued_at, expires_at, nonce (>=16 B), clinical_context_digest (default ""), signature | contracts/messaging.py:39-48 |
| Validation order | sig -> chain -> CN -> revoked serial -> facility -> expires_at>now -> TTL<=15 min -> issued_at<=now+30 s -> consume | breakglass/assertion.py:61-62,300-364 |
| Replay stores | facility: durable (repo); audit: durable (ConsumedIdTable "release_assertion"); authority: in memory | hospital.py:613; audit_service.py:231-233; authority_service.py:250 |
| Commit-then-release | validate+consume -> build event_data -> `with conn.transaction(): append_entry` -> 503 on failure -> seal 3,4 -> return | audit_service.py:394-446; audit/share_custody.py:93-110 |
| Facility order | unseal shares -> validate A -> patient binding -> context -> (join) -> verify event + from/record/actor/reason/time window -> CAS claim -> apply_transition (consume) -> gate -> log rewrap -> register session -> respond | hospital.py:1321-1735 |
| Chain entry | seq, prev_hash, entry_hash, event_type, event_data, actor_id, correlation_id, timestamp, signature | contracts/audit.py:36-44 |
| Chain hash | SHA-256(encode_fields("ehr/audit-chain-link/v1",[h_{i-1}, enc(event_type,event_data), ts, actor])); genesis prev = 32 zero bytes | audit/chain.py:43,62-96 |
| Chain verify | sig -> link+seq -> recomputed hash | chain.py:416-451 |
| Truncation | facility: seq > before only, no signature check; custodian: signature + correlation + seq | api/audit_client.py:101-118; custodian_service.py:474-481 |
| Window | lib default 60 s; deployed 14400 s; min(requested, configured); expiry is inclusive (now >= expires_at); monitor 0.5 s; backoff 1 s doubling, cap 60 s | expiry.py:93-97,155-157,740; deploy/asgi/facility.py:59; hospital.py:1341 |
| AEAD / KDF / sig | AES-256-GCM, 12 B nonce; HKDF-SHA256; ECDSA P-256/SHA-256 | crypto_core/symmetric.py:19,131-158; contracts/base.py:60-61; asymmetric.py:27,45 |
| ElGamal | 256-bit safe prime, g=4; rk = sk_a * sk_b^-1 mod q; reencrypt not called outside pre/ | pre/elgamal.py:22-24,64-93 |
| Search token | HKDF(ikm=K_E, info=prefix + casefold(term)) | search/service.py:98-112 |
| Policy nodes | LEAF, AND (m-of-m split), OR (same secret); leaf AES-GCM with no AAD | contracts/enums.py:125-130; policy/engine.py:192,200-223 |

## Issues

[BLOCKER] paper/tables/transitions.tex:225 (and paper/figures/states.tex:270-271, paper/sections/05-lifecycle.tex:81-83) — The table and figure show EXPIRED->REVOKED as timer-signed only, and §V says "The three expiry-side transitions are signed by a timer-service key". The code also lets the patient sign X->R. The custodian signs `from_state -> REVOKED` from whatever state the facility reports, and the facility revoke endpoint accepts any legal pair whose from_state equals the stored state, so a record left in EXPIRED (during an expiry, or while a failed expiry waits on backoff) can be revoked by the patient with a rotation. — code says: custodian_service.py:1324-1343 (no restriction to GRANTED); hospital.py:1126-1144 (from_state == source_state, to_state REVOKED, legal-set check only); src/lifecycle/state_machine.py:60. — Fix: either add "Patient revokes (record in EXPIRED)" as a second trigger/signer on the X->R row and a `[P]` label on that arrow, and drop "three ... signed by a timer-service key" in favour of "EO->X is timer-signed; X->G/R are timer-signed after the rotation, and X->R may also be a patient revocation", or get the api owner to refuse revocation from EXPIRED (a code change by the owner, not a paper edit).

[BLOCKER] paper/sections/05-lifecycle.tex:77-79 — The paper says the facility "requires its record, actor, reason code and issue time to match the emergency assertion". Issue time is not compared with the assertion. The facility checks event.issued_at against its own clock: no older than 15 min, no more than 30 s in the future. — code says: hospital.py:1600-1607 (`event.issued_at < now - MAX_ASSERTION_TTL or > now + ASSERTION_CLOCK_SKEW`). — Fix: "...requires its record and actor to match the assertion, the same reason code, and an issue time within the last 15 min (30 s skew) on the facility's clock."

[MINOR] paper/sections/05-lifecycle.tex:3-4 — "every change of that state is a signed, replay-protected event": the facility also moves the stored state back by an unsigned compare-and-set when a claimed open or revocation fails (EO->source, REVOKED->source). — code says: hospital.py:1211-1215, 1722-1724. — Fix: "every committed change of state..." or add "(a failed claim is undone by compare-and-set without an event)".

[MINOR] paper/sections/05-lifecycle.tex:181-184 — "each 32-byte block of a secret embeds as one field element". The blocks are taken from a 4-byte length prefix plus the secret, zero-padded, so a 32-byte K_E takes two blocks and gives 66-byte shares. — code says: shamir/split.py:472-496. — Fix: "the secret, prefixed with its 4-byte length and zero-padded, is cut into 32-byte blocks, each one field element; a 256-bit key gives 66-byte shares."

[MINOR] paper/sections/09-evaluation.tex:71 — "a 66-byte share per holder": the audit service holds two shares (132 B). — code says: emergency_key.py:37. — Fix: "a 66-byte share per point (two at the audit service)".

[MINOR] paper/sections/09-evaluation.tex:42 — "PRE re-encrypt is one exponentiation": `reencrypt` also runs a subgroup-membership exponentiation first. — code says: pre/elgamal.py:139-144. — Fix: "two modular exponentiations (membership check and transform)".

[MINOR] paper/sections/06-breakglass.tex:21-25,31-33 — The facility-identifier step in the listed order is meaningful only at the facility. The audit service and the home authority pass `expected_facility_id=assertion.facility_id`, which makes that step trivially true, and check only that the facility is in the federation. — code says: api/share_release.py:107-111,131. — Fix: add "(at the audit service and authority, only that the facility is a federation member)".

[MINOR] paper/sections/06-breakglass.tex:19-20 — The paper says the assertion carries "a digest binding the record and justification texts", but the field is optional (default ""). The holders require it; the facility checks it only when the record's labels require justification or when a digest is present. — code says: contracts/messaging.py:47; share_release.py:112-116; hospital.py:1422-1435. — Fix: "an optional digest ..., which the share holders require".

[MINOR] paper/sections/06-breakglass.tex:37 — "The facility alone checks that the record belongs to A's patient": the custodian checks this too, when a record loader is configured. — code says: custodian_service.py:1418-1421. — Fix: "Of the share holders and the gate, only the facility checks..." or "No share holder checks...".

[MINOR] paper/figures/gate-chain.tex:191-192,220-221 (and 06-breakglass.tex:50, 10-limitations.tex:16-17) — "The gate checks only for three distinct x": on open, the gate first verifies the clinician-signed transition event. It also range-checks x. "Only" is accurate about holders, not about all of the gate's checks. — code says: gate.py:537-546,599-611. — Fix: "checks no share holder, only that at least three distinct x are present".

[MINOR] paper/figures/breakglass-sequence.tex:157 — The facility box starts with "validate A". The code opens (decapsulates) the sealed shares first, then validates A. — code says: hospital.py:1321-1338 before 1355. — Fix: prefix the box with "unseal shares;" or leave the box as is and say in the caption that unsealing comes first.

[MINOR] paper/figures/states.tex:273-275 — "Thick arrows follow a full rotation": on G->R the event is applied and the state claimed before the rotation is stored (hospital.py:1144,1196-1201 then 1205), so "follow" is true only of X->G/R. — Fix: "Thick arrows carry a full rotation (revocation re-keys as part of the transition; expiry re-keys before returning)."

[MINOR] paper/sections/05-lifecycle.tex:131-133,145-147 — "neither re-signs nor mints a second emergency key": true for in-process retries. After a restart, the recovered session has no stored EO->X event, so the timer signs a new one (a new event id). The paper is right that it is not re-emitted. — code says: expiry.py:482-489 (recover_session sets only expired_emitted), 646-660. — Fix: add "after a restart the EO->X event is signed again but not re-logged".

## Round 2

**Summary: 1 BLOCKER, 1 MINOR open** (all 13 round-1 issues RESOLVED; 2 new, both on the new consent wording).

Round-1 status, re-checked against the current tex and src/:
- [BLOCKER] X->R patient-signable — RESOLVED: transitions.tex:20 ("or patient revokes", "Timer or Patient"), states.tex:39 `[T]/[P]` plus caption, 05-lifecycle.tex:81-83.
- [BLOCKER] issue time "match the assertion" — RESOLVED: 05-lifecycle.tex:77-80 now says under 15 min old (30 s skew) on the facility clock (hospital.py:1600-1607).
- [MINOR] unsigned undo — RESOLVED: 05:3 now says "every committed change". This is acceptable: the undo restores the state the record had before the claim.
- [MINOR] Shamir blocks — RESOLVED (05:183-186).
- [MINOR] 66-byte share — RESOLVED ("per $x$", 09:71).
- [MINOR] PRE one exponentiation — RESOLVED ("a subgroup check and one exponentiation", 09:42; the check is itself a modular exponentiation, elgamal.py:47, but the text is no longer wrong).
- [MINOR] holder facility binding — RESOLVED (06:24).
- [MINOR] optional digest — RESOLVED (06:17-18).
- [MINOR] "facility alone" — RESOLVED (06:37-38).
- [MINOR] gate checks only distinct x — RESOLVED (06:51, gate-chain.tex:47, 10:16).
- [MINOR] unseal before validate — RESOLVED (breakglass-sequence.tex:42).
- [MINOR] thick arrows "follow" — RESOLVED (states.tex:42 "carry").
- [MINOR] re-sign after restart — RESOLVED (05:131-133, 145-147).

No regressions found in 03, 04, 05, 06, 07, 09, 10, the figures, transitions.tex or secprops.tex.

New issues (consent wording):

[BLOCKER] paper/sections/00-abstract.tex:5, paper/sections/01-introduction.tex:34, paper/sections/11-conclusion.tex:5-6 — The new text says consent is "a signed read-time check against its GRANTED baseline". "Signed" is true: a ConsentGrant carries the patient's ECDSA signature, which is checked on submission and at read time (contracts/consent.py:110,117; consent/service.py:270,307,413; hospital.py:1004). The rest is wrong. The consent check is against the *grant's own* status, ConsentStatus.GRANTED (consent/service.py:415-433; contracts/enums.py:133-146), and its time window. The read path never reads the record's lifecycle state (hospital.py:728-990 has no lifecycle or state lookup). Because §V calls lifecycle GRANTED "a baseline" (05-lifecycle.tex:19), "its GRANTED baseline" tells the reader that consent is checked against the lifecycle state. — code says: the read with a grant is consent/service.py authorize_read (status GRANTED, not revoked, within decided_at..expires_at, patient signature) followed by the policy-key unwrap; LifecycleState is not consulted. — Fix: "consent is a patient-signed grant checked at read time (status, window and signature), separate from the lifecycle state, which it does not move."

[MINOR] same three lines and tables/related.tex:12 ("consent is a read-time check") — The consent check runs only when the caller presents a grant. Without one, the facility reads through the policy keys alone (hospital.py:812 `if payload.grant is not None`, else 911-916 `decrypt_record_via_policy`). Consent is therefore an optional extra gate on top of the keys, not a check every read goes through. — Fix: add "when a grant is presented; key holders read through the policy alone" (e.g. in the related-table footnote b and §V:19-21).

## Round 3

**Summary: 0 BLOCKER, 0 MINOR open.** Both round-2 issues are resolved, and the five rewritten files contain no new code-truth problems.

- [BLOCKER] "against its GRANTED baseline" — RESOLVED. 00-abstract.tex:5, 01-introduction.tex:28 and 11-conclusion.tex:5-7 now read "a patient-signed grant checked at read time when one is presented (status, window, signature), separate from the lifecycle state". This matches the code: the patient's ECDSA signature (consent/service.py:270,307,413), the status check against ConsentStatus.GRANTED and the decided_at..expires_at window (consent/service.py:415-433). The read path consults no LifecycleState (hospital.py:728-990).
- [MINOR] consent is optional — RESOLVED. "When one is presented" now appears in the abstract, introduction and conclusion, and "when presented" in footnote b of tables/related.tex:12-13. This matches hospital.py:812 (grant path) versus 911-916 (policy-only path).

Other lines checked in the five files, all consistent with the code:
- 01-introduction.tex:18: four states and seven legal transitions (state_machine.py:52-62).
- 02-related-work.tex:58: consent is not a transition and revocation/expiry re-key (hospital.py:1158-1190; api/rotation.py:107-148).
- The abstract's "assertion bound to the record": the audit service requires the record digest (share_release.py:112-125).
- The abstract's "two of four shares" (emergency_key.py:35-37).
- 11-conclusion.tex: commit-then-release (audit_service.py:394-446).

No regressions.
