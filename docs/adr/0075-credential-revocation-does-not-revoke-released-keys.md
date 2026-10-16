# ADR-0075: Credential revocation does not revoke an attribute key already released

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal) → Ojas (authority) → all four (limitation)
- **Task / source:** Review decision D10, option (a); finding F44
- **Affects:** `PROJECT.md` §5 item 9, `ARCHITECTURE.md` "Credential lifecycle"; records the trade ADR-0026 and ADR-0028 left implicit

## Context

Each authority keeps one attribute key per `(name, value)`
(`authority/issuance.py`), shared by every holder and never rotated. Revoking
a credential (ADR-0028, ADR-0029) makes the authority refuse to release the
key again; a holder who already has the key keeps it. Record rotation
(ADR-0036 revocation, ADR-0069 expiry) re-seals the record under a new root
secret, but the leaves are still encrypted to the same attribute keys, so a
revoked clinician who kept a key still satisfies any leaf naming it.

## Decision

Document it as a limitation (D10-a): `PROJECT.md` §5 item 9 and
`ARCHITECTURE.md` "Credential lifecycle". No code change.

## Consequences

- The paper's limitations must say that credential revocation is
  forward-only for key *release*, not for keys already held, and that record
  rotation does not help against a kept attribute key.
- Record-level revocation (ADR-0036) is unaffected for a party excluded by the
  new policy: it is the policy change, not the credential, that removes them.
- Fixing it needs epoch-versioned attribute keys and re-authoring every record
  whose policy names a rotated attribute (D10-b). Future work.

## Alternatives considered

- **D10-b: epoch-versioned attribute keys** — the real fix, but every record
  naming the attribute must be re-compiled when an epoch advances, and the
  authorities need per-epoch key state; out of scope for this phase.
