# ADR-0077: Signed, hashed and AAD bytes are domain-tagged and length-prefixed

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal; owns `records/`) → Powel (crypto_core, breakglass, lifecycle, consent), Ojas (audit, authority) → all four
- **Task / source:** Review decision D9, option (a), finding F23; finding F29
- **Affects:** new `src/crypto_core/encoding.py`; `src/lifecycle/state_machine.py`, `src/breakglass/assertion.py`, `src/breakglass/envelopes.py`, `src/consent/service.py`, `src/authority/issuance.py`, `src/audit/chain.py`, `src/records/service.py`, `src/breakglass/gate.py` (comment only); amends ADR-0034's field-separator encoding

## Context

Six modules built signed or hashed bytes by joining fields with `0x1f`.
`Identifier` allows `0x1f`, so one byte string could be read as different
field lists: a consent request for the one record `"rec-1\x1frec-2"` signed the
same bytes as one for `("rec-1", "rec-2")`. The credential payload also joined
attribute name and value with `:`. There was no type tag, and since ADR-0068
the clinician's key signs both emergency assertions and transition events, so
signatures could in principle be reused across types. Separately (F29), a DEK
wrapping's AAD bound only `record_id`, so an old-generation wrapping could be
put back as the current one.

## Decision

1. `crypto_core.encode_fields(domain, fields)` writes the domain tag and then
   every field, each prefixed by its 4-byte big-endian length. The byte string
   decodes to exactly one `(domain, fields)` list. It is an encoding, not a new
   primitive: it only decides which bytes the existing ECDSA, SHA-256 and
   AES-GCM calls cover.
2. Every signed or hashed payload uses it with its own domain:
   `ehr/transition-event/v1`, `ehr/emergency-assertion/v1`,
   `ehr/request-envelope/v1`, `ehr/consent-request/v1`,
   `ehr/consent-grant/v1` (scope nested under `ehr/consent-scope/v1`),
   `ehr/attribute-credential/v1` (name and value now separate fields),
   `ehr/audit-event/v1`, `ehr/audit-chain-link/v1`, `ehr/audit-entry/v1`.
   The assertion's optional context digest is now always present (empty when
   unused), so the field count is fixed.
3. The DEK wrapping AAD is
   `encode_fields("ehr/dek-wrapping/v1", [record_id, wrapped_for, generation])`.
4. ADR-0064's patient-label signature keeps its JSON-array encoding; it is
   already domain-tagged and unambiguous.

## Consequences

- Signatures, chain hashes and wrappings made before this change no longer
  verify or unwrap. Every deployment path resets its store at bootstrap
  (`run_local`, Compose bootstrap), so there is no migration; a persistent
  database from before this change must be re-seeded.
- The `0x1f` field-separator description in ADR-0034 is superseded; its
  JSON canonicalisation of `event_data` and whole-entry signing stand.
- Tests: `tests/security/test_signed_encoding.py` (consent scope cannot be
  re-split, domains differ, a relabelled generation or policy does not
  unwrap).
- The chain formula in ARCHITECTURE C10, `h_i = SHA-256(h_{i-1} ‖ event ‖
  timestamp ‖ actor)`, is unchanged in meaning; `‖` is now this encoding.

## Alternatives considered

- **D9-b: forbid `0x1f` in `Identifier`** — a `contract:` PR that closes the
  separator ambiguity only for identifiers (not nonces, digests or free text
  such as `purpose`), and leaves cross-type reuse open.
- **A canonical JSON array per payload (as ADR-0064)** — also unambiguous, but
  raw bytes (nonces, hashes, request bodies) would need a second encoding
  inside the JSON; length prefixes take bytes as they are.
