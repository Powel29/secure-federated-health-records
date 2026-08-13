# ADR-0001: Reject Charm-Crypto; hand-roll the exotic primitives

- **Status:** Accepted
- **Date:** 2026-08-12
- **Deciders:** Team (Powel, Nandini, Ojas, Avaneeth)
- **Task / source:** ARCHITECTURE.md §1 (backfilled when the decision log was set up)
- **Affects:** `crypto_core`, `shamir`, `pre`, `policy`; the whole install story

## Context

Multi-authority attribute-based access sits on the critical path. The obvious
library, Charm-Crypto, depends on the PBC and GMP C libraries, has patchy
Python 3 support, and routinely costs teams one to two weeks just to build. The
governing project constraint is "keep it easy to install and run" — a stack that
takes two weeks to stand up is a schedule risk disguised as sophistication.

## Decision

Do not use Charm-Crypto. Use `cryptography` (pyca) for the standard primitives
(AES-256-GCM, HKDF, ECDSA P-256, RSA-OAEP, X.509) as pure wheels, and hand-roll
the three things no easy-install library provides: Shamir SSS over GF(p), an
ElGamal-style unidirectional PRE, and the policy-tree access structure.

## Consequences

- Clean `pip install` on all four machines with no C toolchain — the T01 exit
  criterion.
- Hand-rolled crypto is our own responsibility to get right, which is why
  CONVENTIONS.md §2 exists and why every construction must trace to
  ARCHITECTURE §3/§8. This is a course project and these are course topics, so
  the trade is acceptable and even pedagogically useful.
- We forgo pairing-based CP-ABE's collusion resistance — see ADR-0002.

## Alternatives considered

- **Charm-Crypto** — rejected for the build/install risk on the critical path.
- **A different pairing library** — same class of C-dependency problem.
