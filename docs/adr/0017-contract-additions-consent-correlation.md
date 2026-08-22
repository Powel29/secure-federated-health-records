# ADR-0017: Contract additions for consent and correlation, and RequestEnvelope reconciliation

- **Status:** Proposed — this is a `contract:` change and needs **all four**
  members' approval before merge (CONVENTIONS.md §3).
- **Date:** 2026-08-21
- **Deciders:** Powel → all four
- **Task / source:** ADR-0014 (consent, notifications, correlation IDs),
  ADR-0015 (strictness cuts), ADR-0016 (patient self-access)
- **Affects:** `src/contracts/` (frozen set), and its consumers in `audit`,
  `policy`, `lifecycle`, `authority`, and the web portals (`ui`)

## Context

The nine contracts were frozen in Phase 0 (T02). The 2026-08-18 decisions then
outran the freeze:

- **ADR-0014** adopts a patient consent model (*signed, scoped, expiring,
  request-then-approve*), *correlation IDs on audit events*, and an admin portal
  that browses the audit log **by correlation ID** — but no frozen schema
  represents a consent request/decision, and `AuditEntry` has no correlation
  field.
- **ADR-0015** cut service-request signing as a separate "replace mTLS" control,
  yet `RequestEnvelope`'s docstring still claimed *service identity* as one of
  its purposes — a three-way inconsistency with ADR-0015 and the ADR-README
  "Owed" list.
- **ADR-0016** makes a patient a possible credential subject; `AttributeCredential`
  documented its subject as "the clinician."

`TransitionEvent` cannot stand in for consent: it is a *completed* state change
with no scope, no expiry (deliberately, per its own note), and no pending-request
notion. Correlation could be smuggled into `AuditEntry.event_data`, but a value
the portal queries and groups by should be a typed, guaranteed field.

## Decision

Amend the frozen contract set (a `contract:` PR):

1. **Add `ConsentRequest` and `ConsentGrant`** (`contracts/consent.py`) and a
   `ConsentStatus` enum. They are the two messages of request-then-approve:
   scoped to specific `record_id`s, time-boxed by `expires_at`, and signed — the
   request by the grantee, the grant by the patient. They record signed *intent*
   only; keys and the threshold gate still decide access (ADR-0014 boundary).
2. **Add a required `correlation_id: Identifier` to `AuditEntry`.** Every entry
   of one logical flow shares it, so the admin/audit portal can reconstruct a
   flow end to end.
3. **Reconcile `RequestEnvelope` with ADR-0015 (docstring only, no shape
   change).** Its purpose is restated as replay protection + payload integrity;
   the "separate service-identity control replacing mTLS" framing is removed —
   service identity comes from the PKI and cross-certification (P2-1). The
   ADR-README "Owed" entry is updated to point here.
4. **Clarify `AttributeCredential`** (docstring only): the subject may be a
   patient (ADR-0016), not only a clinician.

The frozen set becomes **eleven** schemas.

## Consequences

- `correlation_id` is **required**, so every `AuditEntry` construction site must
  supply it. Cheap now (Phase 1, nothing built on it yet); it would be expensive
  later. A system/genesis entry uses a dedicated boot correlation id rather than
  a magic empty value.
- Two new schemas widen the all-four review surface once, but close the largest
  gap — consent was wholly unrepresented.
- No wire/shape change to `RequestEnvelope` or `AttributeCredential`: those two
  edits are documentation, safe to merge without a data migration.
- **Honest downside:** this is the second post-freeze amendment (after the §8
  review's two additions). A contract "frozen" and then amended twice is a signal
  the freeze happened before the design settled; ADR-0014/0015/0016 landing after
  T02 is the root cause. The mitigation is that each amendment goes through the
  same all-four gate, so "frozen" still means "no silent change," which is the
  property that matters.

## Alternatives considered

- **Put correlation and consent inside `AuditEntry.event_data` / reuse
  `TransitionEvent`.** Rejected: an untyped dict is not something to query and
  enforce on, and `TransitionEvent` lacks scope/expiry/pending-request — it would
  have to grow those anyway, which is the same change with worse ergonomics.
- **Delete `RequestEnvelope.signature` to match the ADR-0015 cut.** Rejected:
  the signature still provides envelope integrity and one-time binding
  (anti-replay authenticity); removing it is a real security downgrade, and
  ADR-0015 cut the *separate identity layer*, not envelope integrity. Left to a
  future ADR if the team wants it.
