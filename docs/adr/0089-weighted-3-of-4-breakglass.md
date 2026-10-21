# ADR-0089: Break-glass is a weighted 3-of-4 split; the home authority holds share 2

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Powel (breakglass, lifecycle) → Ojas (audit, custodian, authority services), Avaneeth (api, deploy) → all four (it changes the access structure behind claim C3)
- **Task / source:** proposal "Break-Glass 3-of-4" (2026-10-21); supersedes ADR-0074
- **Affects:** `breakglass.emergency_key`, `custodian`, `lifecycle.rotation` (unchanged code, new split), `api/audit_service`, `api/authority_service`, `api/custodian_service`, `api/hospital`, `api/rotation`, `api/share_release` (new), `audit.share_registry`, `audit.share_custody`, `deploy/`, `demo/`, `wire/`; ARCHITECTURE.md C10/C11/§5/§8; PROJECT.md §1, §5 item 8; threat model

## Context

ADR-0074 kept the 2-of-3 split but never deposited share 2. A home authority
holding it would let shares 1 + 2 open a record with no audit entry. So
break-glass needed share 1 (the custodian) **and** share 3 (the audit
service), with no fallback.

Two facts about this build shape what a fallback can do:

1. The custodian is the clinician's key agent (ADR-0043). It signs the
   emergency assertion and opens the delivered DEK, so a custodian *outage*
   blocks break-glass whatever the share structure.
2. The custodian keeps share 1 in process memory. A custodian restart loses
   every share 1, and break-glass then fails for every record until it is
   re-keyed.

The aim is a fallback for the loss of share 1 that keeps "no log entry, no
key" unconditional, using only the existing Shamir (k, n) construction.

## Decision

1. **Split.** `split_emergency_key` produces a Shamir **3-of-4** sharing
   (`THRESHOLD = 3`, `TOTAL_SHARES = 4`), with fixed holders:
   - x = 1: the custodian (clinician custody);
   - x = 2: the patient's **home authority**, the authority that issued the
     patient's `owner` credential;
   - x = 3 and x = 4: the **audit service**.

   Two shares to one holder is Shamir's own weighting device, not a new
   construction. Any single holder has at most 2 points and learns nothing.
   Custodian + home authority have 2 and learn nothing. Audit + custodian, or
   audit + home authority, have 3 and reconstruct. So every reconstruction
   includes the audit service.
2. **Each holder takes only its own shares.** A deposit or replacement whose
   share indices are not exactly the holder's set ({1}, {2} or {3, 4}) is
   refused. A misrouted share therefore cannot quietly give a
   custodian-plus-home-authority pair three points.
3. **The audit service** holds shares 3 and 4 together and releases both in
   one response, with the gate unchanged: validate the assertion (ADR-0067),
   commit the entry, then release both sealed to the facility gate
   (ADR-0079).
4. **The home authority** releases share 2 only after it has done three
   things:
   - validated the emergency assertion itself, with the same five-point check
     and record binding as the audit service, against its own trust anchors;
   - checked the assertion against its own consumed-assertion store;
   - verified the recipient as a root-certified facility.

   It seals share 2 to that facility's gate. It writes no audit entry: share 2
   opens nothing without shares 3 and 4, and the audit service logs every
   release of those. The validation is shared code, `api.share_release`, so
   both holders run the identical check.
5. **The custodian** presents share 1 when it holds one. When it doesn't (for
   example after a restart), it fetches share 2 from the patient's home
   authority *before* asking the audit service, so a refusal costs no audit
   release. It then asks the audit service for shares 3 and 4, and the audit
   entry records `unlock_path` (`custodian` or `home_authority`).
6. **Rotation** (expiry, ADR-0069; revocation, ADR-0080; recovery, ADR-0081)
   hands out all four shares: share 1 to the custodian, share 2 to the owner
   authority named by the record policy's `owner` leaf, and shares 3 + 4 to
   the audit service. Each holder accepts a replacement only from a facility,
   only while the store shows the record `expired` or `revoked`, and only for
   a later generation. For that check the authority gets the same read-only
   lifecycle lookup the custodian has.

## Consequences

- "No log entry, no key" holds without exception, and no single holder
  (including the audit service) can open a record. Claim C3's statement is
  unchanged; its tests gain the 3-of-4 cases: custodian + home refused, audit
  alone refused, both audit pairs open.
- **What the fallback covers:** break-glass survives the loss of share 1 (a
  custodian restart). **It does not cover** a custodian outage (the custodian
  is the clinician's key agent) or any audit-service failure. The audit
  service is still a single point of availability, and its shares are in
  memory too, so an audit restart loses shares 3 + 4 for every record. Both
  are stated in PROJECT.md §5 item 8.
- **One more path in:** compromising the home authority *and* the audit
  service now opens a record, as compromising the custodian and the audit
  service already did. Both paths still pass the audit service's assertion
  check and log entry.
- The authority services gain share custody, a share-sealing key at
  `GET /share-key`, and read access to the store's lifecycle state. Their
  consumed-assertion store is in memory: after an authority restart a replayed
  assertion could fetch share 2 again, but the audit service's persistent
  store still refuses it, so nothing opens.
- Ingest and every rotation make one more deposit. If the home authority is
  unreachable at ingest the upload fails (shares first, ingest second, review
  F4). If it is unreachable at rotation the rotation retries, as for the other
  holders.
- Wire evidence changes: the release response carries two sealed shares, and
  the canary manifests gain shares 2 and 4, so claim 1 covers them. The
  captures must be re-recorded.

## Alternatives considered

- **Keep ADR-0074 (2-of-2).** No fallback: losing share 1 (a custodian
  restart) blocks break-glass for every record.
- **Nested AND/OR: audit AND (custodian OR home), with C and H holding
  identical copies.** The same access rule, but a leak at the home authority
  exposes a copy of the custodian's share, and a log can't tell which one was
  used. The weighted split keeps the two points distinct.
- **2-of-3 with share 2 deposited, and the home authority also validating and
  committing to the audit chain.** A real 2-of-3, but it needs a second logger
  and log reconciliation (ADR-0074's own objection). Future work.
- **Home authority as a mandatory approver (3-of-3).** Dual control, but
  emergencies become less available, not more.
- **Merkle-log gate (transparent decryption).** It would also remove the
  trust in the audit service (PROJECT.md §5 item 13), but it is new design
  work. Future work.
