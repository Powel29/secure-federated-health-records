# ADR-0073: §4A claim 1 ("no plaintext on the wire") is scoped to the TLS profile

- **Status:** Proposed; shares sealed on every profile by ADR-0079
- **Date:** 2026-10-15
- **Deciders:** Avaneeth (proposal) → Powel (wire analyser) → all four (claim change)
- **Task / source:** Review decision D6, option (b); ADR-0045 left the default to D6
- **Affects:** `PROJECT.md` §4A, `wire/checks.py`, `wire/analyze_traffic.py`, `tests/wire/test_live_capture.py`; resolves ADR-0045's open default

## Context

§4A claim 1 said no PHI, DEKs, attribute keys or shares cross the wire in the
clear. On the plain profile they do: the facility decrypts for reads and
encrypts at ingest, so plaintext, the DEK, the emergency key and authoring
keys travel in request and response bodies. D6 offered (a) client-side crypto
in the custodian, a large change across three owners, or (b) scope the claim
to TLS and say so. ADR-0045 made the analyser's `--claim1-scope` default
`all`, which fails, until D6 was decided.

## Decision

Take D6-b, after removing private keys from facility requests (ADR-0072):

- Claim 1 holds **under the TLS profile**. `--claim1-scope` now defaults to
  `tls` (CLI, `run_all`, the live-capture test). The plain capture is the
  positive control that proves the detector finds secrets.
- On the plain profile, what the application layer does protect is stated:
  no read, revocation or break-glass request carries a private key
  (ADR-0068, ADR-0072); keys reach the custodian only at enrolment.
  Shares travel sealed on every profile (ADR-0079); plaintext, DEKs and
  attribute keys rely on TLS in transit.
- `--claim1-scope all` stays available and reports what an observer of an
  unencrypted link sees.
- `PROJECT.md` §4A now says this in the claim itself.

## Consequences

- E4 claim 1 can pass from fresh captures; it is a weaker, honest claim.
- The paper must state that confidentiality of plaintext, DEKs and attribute
  keys in transit relies on TLS, and that client-side crypto (D6-a) is future
  work.
- The analyser does not assert ADR-0072's guarantee on the wire; the schema
  test does. A follow-up could add a plain-profile check for private keys
  only, but key provisioning to the custodian (`/subjects/{id}/material`)
  legitimately carries keys at enrolment and would need an exemption.
- Wrapping shares to the gate (the review's D6 step 2) is done in ADR-0079,
  which also makes a plain-capture share fail claim 1 in either scope.

## Alternatives considered

- **D6-a, client-side crypto** — the claim the paper wanted, but a large
  change to ingest, read and break-glass across three owners; not feasible in
  the remaining phase.
- **Leave the default at `all`** — keeps E4 permanently red over a decision
  already taken.
