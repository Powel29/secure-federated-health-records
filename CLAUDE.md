# CLAUDE.md

Federated Break-Glass EHR with a Unified Key-Lifecycle State Machine.
Information Security lab project (ICT 3121) — 4-person team: Powel, Nandini,
Ojas, Avaneeth.

**Read this file first, then load only the file you need.** Detail lives in the
four documents below and is not duplicated here.

---

**`PROJECT.md`** — What we are building and why.
Scope statement, deliverables, grading criteria (unconfirmed — see the open
faculty questions), the **required course security module** (§4A — Traffic
Analysis), the novelty claim and papers we
extend, the honesty caveats that must appear in the paper, and the explicit
out-of-scope list, and the **disposition of the external security review**
(§4B — what was adopted, what was rejected, and why).
*Go here before adding a feature or agreeing that something is in scope.*

**`ARCHITECTURE.md`** — How it is built.
Tech stack and why Charm-Crypto was rejected, the 16 components, our
secret-sharing access structure that substitutes for CP-ABE, the **application
security model** (§8 — emergency assertion, replay, service identity,
credential lifecycle), the full dependency map and critical path, data/request flow for normal reads, revocation and
cross-facility break-glass, repository layout, and the deployment topology and
bootstrap sequence.
*Go here before writing a module or changing how two modules talk.*

**`CONVENTIONS.md`** — How we write code.
Style and typing rules, the seven crypto-specific rules that are correctness
requirements rather than preferences, module ownership and the contract-change
process, commit message format, and testing requirements including the negative
security tests that serve as evidence for the paper.
*Go here before your first commit, and re-read §2 before touching crypto.*

**`WORKFLOW.md`** — Who does what, in what order.
The seven gated phases with exit criteria, the Build Order (what blocks
everything vs. what can run in parallel, grouped by person), the full task table
with owners and dependencies, git branching and merge rules, sync cadence, and
the deployment/release procedure.
*Go here to find out what to work on next or whether something is unblocked.*

---

## Agent skills

Project-specific skills live in `.claude/skills/`. They load on trigger and
carry procedural depth; this file carries the always-true rules. Do not
duplicate content between them — a rule in both places will drift and then
contradict itself.

- **`crypto-implementation`** — rules and guardrails for any cryptographic code.
  The governing rule: never invent a construction not specified in
  `ARCHITECTURE.md` §3 or §8. Load for anything under `crypto_core`, `shamir`,
  `pre`, `policy`, `records`, `lifecycle`, `breakglass`, `audit`, `search`.
- **`negative-security-test`** — how to write tests that prove a control fails
  closed. Load for anything under `tests/security/` or when implementing a
  control (a control without its negative test is not finished).
- **`benchmark-methodology`** — measurement, results schema, and plotting so the
  evaluation is reproducible. Load for anything under `bench/`.
- **`ieee-paper`** — paper structure, claim-to-evidence discipline, and the
  limitations that must appear in the abstract. Load for anything under
  `paper/`.

**`docs/dashboard-design.md`** — Build spec for the four-pane demo dashboard
(T55): grid, per-pane queries and layout, the states it must handle, visual
rules, and what is deliberately out of scope.

**`docs/adr/README.md`** — The decision log. The tracker table lists every
decision taken so far, by whom, and its status; each row links to a one-file ADR
with the full context. Read it to see what has been decided; add to it whenever
you decide something (see the standing rule below and `CONVENTIONS.md` §6).

---

## Standing rules that override convenience

- **Every decision with alternatives gets logged.** When anyone makes a choice
  — a library, an algorithm, a contract change, a CI or deployment change, a
  security control, or reversing something in the four docs — write an ADR in
  `docs/adr/` and add its row to the tracker in `docs/adr/README.md`, in the
  same PR. The tracker is the single place to see every decision and who made
  it. The channel message where it was decided is not the record; the ADR is.
- **`src/contracts/` is frozen** after Phase 0. Changes need a `contract:` PR
  approved by all four.
- **One owner per `src/` module.** Do not edit someone else's directory, even
  for a one-line fix.
- **All crypto goes through `crypto_core`.** No direct `hazmat` imports
  elsewhere.
- **Fail closed.** Missing share, bad signature, mismatched chain head — raise,
  never degrade gracefully.
- **No real patient data. No key material in git. Ever.**
- **The required course module (Traffic Analysis) ships as PyShark code that
  asserts wire-level properties**, not as screenshots. Faculty requirement is
  implementation and demonstration, not mention. See `PROJECT.md` §4A.
- **Capture only our own synthetic federation** — loopback or the Docker bridge.
  Never campus, shared, or third-party networks.
- **Break-glass requires a valid signed Emergency Assertion.** "The clinician
  asserts an emergency" is not a specification — see `ARCHITECTURE.md` §8.
- **Do not re-add the ML anomaly-detection layer** or FHIR/HL7 interoperability.
  Both were cut deliberately; see `PROJECT.md` §6.
- **Phases are gated, not dated.** A phase ends when its exit criteria are
  demonstrated from a clean clone, not when it feels done.
