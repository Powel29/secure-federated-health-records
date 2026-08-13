# ADR-0003: Simulate the HSM/KMS emergency timer with a trusted service

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** Team (Powel, Nandini, Ojas, Avaneeth)
- **Task / source:** ARCHITECTURE.md §7, PROJECT.md §5 item 2 and §6 (backfilled)
- **Affects:** `lifecycle`, `breakglass`; the threat model; the paper's limitations

## Context

Emergency access is time-boxed: an emergency key must expire. Real enforcement of
"this key stops working at time T" belongs in an HSM/KMS. We have no HSM, and
buying/emulating real hardware is out of scope for a security course project.

## Decision

Simulate the HSM/KMS timer with a trusted service process. Expiry is implemented
as a **signed, logged forced rotation** rather than a hardware guarantee, so
subverting expiry is tamper-evident rather than silent.

## Consequences

- Keeps the project installable and demonstrable with no special hardware.
- **Documented limitation:** a compromised server could decline to expire an
  emergency key. We reduce but do not eliminate this — the signed, logged
  rotation makes non-expiry detectable in the audit chain. Must appear in the
  threat model and the paper (PROJECT.md §5 item 2).
- The emergency time-box length is configuration (ARCHITECTURE.md §7), not
  hardcoded.

## Alternatives considered

- **Real HSM hardware** — out of scope; cost and setup dwarf the pedagogical
  value.
- **Pure-cryptographic expiry** — no sound construction expires a key without a
  trusted clock/enforcer; this would overclaim.
