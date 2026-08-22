# ADR-0015: Strictness-pass cuts (service-signing, plain-HTTP guard, BOLA middleware)

Status: Accepted (2026-08-18) — partially reverses adoptions made from the
external security review

## Context
A strict review of the plan asked whether any feature was being implemented
without earning its place. Three tasks adopted earlier from the external security
review were found to be production-security reflexes that do not serve this
project's goals (novelty, paper, required course module).

## Decision
- **Cut service-request signing (old T53/P4-8).** Redundant with the PKI and
  cross-certification already built (P2-1); it authenticated services that
  already authenticate. It existed to "replace mTLS," but nothing needs to
  replace mTLS — payloads are already encrypted and the threat model does not
  require confidential transport.
- **Cut the plain-HTTP capture guard (old T54/P4-9).** It guards against
  accidentally deploying in capture mode; a 4-person lab project on laptops has
  no deployment in which that failure can occur.
- **Fold BOLA (old T51/P4-7) into a test.** The crypto layer already prevents an
  unauthorised caller from decrypting; the only residual risk is patient-ID
  enumeration, which is proven by one test in P5-1 rather than a middleware layer.

## Reason recorded
These were over-adoptions from an audit that was itself scoped to production
web-app security — a frame explicitly noted as overscoped when the review was
processed. Judged against this project's actual goals, they buy nothing graded or
publishable.

## Consequences
- ~9h removed, all from Ojas (113h → ~104h).
- The `plain-HTTP capture mode` itself remains (it is how traffic analysis works);
  only the start-up *guard* around it is cut.
- P5-1 gains the enumeration test.
- Novelty, paper, and the required course module are untouched.
