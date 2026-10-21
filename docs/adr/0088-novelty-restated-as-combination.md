# ADR-0088: The novelty claim is a combination; log-gated release is prior art

- **Status:** Proposed
- **Date:** 2026-10-21
- **Deciders:** Powel → all four (it changes the paper's headline claim)
- **Task / source:** `docs/review/2026-10-21-novelty-publishability-review.md` (from `docs/novelty-research-handoff.md`); PROJECT.md §4
- **Affects:** `PROJECT.md` §4 and §5 (new item 13); root `SKILL.md` (removed); `docs/explainers/01`, `08`; `docs/novelty-research-handoff.md`; `.claude/skills/ieee-paper/`; `docs/plans/ieee-paper-oneshot-prompt.md`

## Context

`PROJECT.md` §4 said "no prior work … makes logging a cryptographic
precondition of break-glass". It also said arXiv 2511.17464 "already does
revocation-as-key-rotation".

An external literature review (filed 2026-10-21) found both wrong:
- Log-gated decryption is the stated thesis of accountable and transparent
  decryption: Kroll et al. 2018; Ryan 2017; Cheval, Moreira and Ryan,
  EuroS&P 2023; Larch, OSDI 2023; PORTEX, TIFS 2025. Kroll et al. even name
  hospital emergency access as an application.
- 2511.17464 is shown to do signed, time-bounded, audited grants with key
  wrapping, not rotation.

The review also showed that prior transparent-decryption logs are untrusted
(proofs of presence and extension), while ours is a trusted hash chain.

The rest of its harshest findings described the code as of around
2026-10-09, and have since been fixed: the 2-of-3 bypass (ADR-0074), the
assertion check (ADR-0067) and the expiry shares (ADR-0069). The filed copy
carries a status note saying which findings are out of date.

## Decision

1. `PROJECT.md` §4 now states the novelty as a **combination, implemented**:
   one signed key lifecycle for consent, revocation, break-glass and expiry;
   transparent-decryption-style log gating instantiated for federated
   break-glass, with a mandatory audit share and an assertion check before
   commit; emergency-scoped search; and test and wire evidence. Transparent
   decryption is listed as the primitive we instantiate. The paper never
   claims to be first to gate key release on logging.
2. 2511.17464 is cited for signed, time-bounded, audited grants, not for
   rotation.
3. Kroll et al., transparent decryption and de Oliveira et al. are added as
   rivals, each with a one-line delta.
4. `PROJECT.md` §5 gains item 13: the audit service is trusted, with no
   proofs of presence or extension.
5. The paper's related work starts from the review's bibliography, treated as
   **leads**. Every entry is checked against its DOI, arXiv id or publisher
   page before it is cited, because some of the review's numbered sources don't
   match their claims.
6. The old `SKILL.md` at the repo root (an earlier `ieee-paper` skill from
   commit `22ef588`, outside `.claude/skills/`) is removed. It repeated both
   outdated claims, and "four caveats". Its rules that are still valid (the
   security-properties table, figures matching the code, the simulated
   federation, `\cite{TODO-…}` while drafting) moved into
   `.claude/skills/ieee-paper/SKILL.md`, so only one copy of the rules
   exists (CLAUDE.md: no duplicated rules between skills).

## Consequences

- The headline claim gets smaller but survives review. A reviewer who knows
  transparent decryption would otherwise reject the paper on the first page.
- The paper has to position against a stronger primitive and admit our log is
  weaker. Merkle proofs checked by the facility, and a ProVerif model of
  commit-before-release, become the obvious future work.
- Realistic venues are a security workshop or an applied journal, not a
  top-tier conference. The project is assessed internally anyway (§3 Q4).
- Explainers 01 and 08 change their novelty answers. The viva answer changes
  from "first to make logging a precondition" to "the combination, and here
  is what we instantiate".

## Alternatives considered

- **Keep the original claim.** It is false on current evidence, and an
  examiner who knows the area would catch it.
- **Drop log-gating from the claims entirely.** That undersells the build: no
  prior work found applies it inside a consent/revocation/break-glass lifecycle
  for federated health records, with a mandatory audit share bound to a
  signed emergency assertion.
- **Make the log untrusted (Merkle proofs) before restating.** That's the
  right technical fix, but it is new design work. It is recorded as future
  work and a limitation instead of blocking the paper.
