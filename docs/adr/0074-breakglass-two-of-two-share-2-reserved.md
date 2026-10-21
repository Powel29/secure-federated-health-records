# ADR-0074: Break-glass is 2-of-2 in this build; share 2 is reserved

- **Status:** Superseded by ADR-0089
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal) → Powel (breakglass), Ojas (custodian, authority) → all four (claim change)
- **Task / source:** Review decision D2, option (b); finding F3
- **Affects:** `PROJECT.md` §1 and §5 item 8, `ARCHITECTURE.md` C11 and §5 step 3–4, `docs/threat-model.md`; comments in `src/custodian/__init__.py`, `src/api/custodian_service.py`, `src/api/rotation.py`

## Context

The emergency key is split 2-of-3 for the clinician (custody), the patient's
home authority (or delegate) and the audit service. Only shares 1 and 3 are
deposited; share 2 is generated and thrown away at ingest and at every expiry
rotation (ADR-0069). The documents claimed a working 2-of-3 gate with a
home-authority fallback.

Depositing share 2 is not a small change. The headline claim is "no log entry,
no key": the audit service releases share 3 only after committing an entry and
validating the assertion (ADR-0067). With share 2 at the home authority,
shares 1 + 2 would reconstruct the key without the audit service, so the home
authority would also have to validate the assertion and commit to the audit
chain before releasing. That is a second share-holder service with the full
ADR-0067 check.

## Decision

State the gate as it is: the split stays 2-of-3, share 2 is **reserved and not
deposited**, so break-glass needs share 1 and share 3 (2-of-2 in practice).
The project documents, threat model and code comments say so. The gate's code
does not change; it still accepts any two valid shares.

## Consequences

- "No log entry, no key" holds unconditionally, because every reconstruction
  needs the audit service's share.
- There is no fallback: if the custodian or the audit service is down,
  break-glass is unavailable. The paper must say this.
- The no-single-shareholder property (§5 item 3) still holds: the custodian
  and the audit service each hold one share.
- The threat model's rogue authority holds no break-glass share.
- Depositing share 2 is future work, with the condition above: its holder must
  validate the assertion and commit an audit entry before release.

## Alternatives considered

- **D2-a: deposit share 2 with the home authority now** — keeps the 2-of-3
  claim but, without an audit commit at the authority, lets shares 1 + 2 open
  a record with no log entry, which breaks the headline claim. With the
  commit, it is a second ADR-0067 implementation; not feasible this phase.
- **Make the split 2-of-2** — changes `breakglass.emergency_key`, the seed and
  the rotation code for no gain; keeping the 2-of-3 split leaves room for
  share 2 later.
