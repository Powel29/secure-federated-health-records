---
name: ieee-paper
description: How to draft, structure, and check the research paper for this federated EHR project, including claim-to-evidence discipline and the limitations that must be stated up front. Use this skill whenever writing or editing anything under paper/, drafting an abstract, introduction, related work, system design, security analysis, evaluation, or limitations section, or when asked to describe the contribution, the gap, or the novelty in prose.
---

# Writing the paper

The paper is a deliverable of equal weight to the code (`PROJECT.md` D3). Its
credibility rests on two things: every claim tracing to evidence, and the
limitations being stated before a reader finds them.

## Structure

Standard IEEE conference structure, LaTeX source in `paper/`:

1. Abstract
2. Introduction — problem, why existing work is insufficient, contributions
3. Related work — the two anchors, the two nearest rivals
4. System design — the state machine, the access structure, the threshold gate
5. Security analysis — threat model, properties, and their evidence
6. Implementation
7. Evaluation
8. Limitations and future work
9. Conclusion

Section ownership is in the `WORKFLOW.md` task table (T40, T40b, T41, T42, T43).
Check it before drafting — writing into someone else's section creates the same
collision problem as editing their module.

## The contribution, stated precisely

Four contributions, in `PROJECT.md` §4. State them as a unification claim, not
as a list of features:

> Existing work treats consent, revocation, and break-glass as separate
> mechanisms, and audit logging as a bypassable policy promise.

The novelty is that they become **one key-lifecycle state machine** in which
every transition is a signed key-rotation event, and in which logging is a
cryptographic precondition of emergency access rather than an obligation.

Do not overstate. `arXiv 2511.17464` already does revocation-as-key-rotation —
cite it, and be explicit that our delta is the unification, not rotation itself.
A reviewer who finds an uncited near-rival stops trusting the rest of the paper;
one who sees it cited and honestly distinguished trusts more.

## Claim-to-evidence discipline

**Every security claim must name the test that backs it.** The negative test
suite (`tests/security/`) exists for this. When drafting the security analysis,
work from the test list and write claims you can point at — not the reverse.

**Every performance number must come from a benchmark run**, reproducible from
`bench/results/` by one command. Never write a number from memory, from an
earlier draft, or from a run whose environment is unrecorded.

If a claim has no test and no benchmark, either build the evidence or remove the
claim. There is no third option that survives a viva.

## Limitations go in the abstract

Four caveats, stated in `PROJECT.md` §5. These belong up front, not buried in a
limitations section a reader may reach after forming a bad impression:

1. Revocation is forward-only — already-decrypted plaintext cannot be retracted.
2. Emergency expiry is server/HSM-enforced, not pure cryptography. Mitigated by
   making expiry a signed, logged rotation, so subversion is tamper-evident
   rather than silent.
3. No single shareholder, including the audit service, can open a record —
   claimed *and tested*.
4. The access structure is not full CP-ABE and is **not collusion-resistant**:
   two clinicians could pool attribute keys to satisfy a policy neither
   satisfies alone. Pairing-based CP-ABE prevents this by binding attribute keys
   to a per-user random value; we cannot without pairings.

The fourth is the one most likely to be found by a reviewer, and volunteering it
converts a potential objection into evidence of rigour.

Likewise state the security-properties table (`WORKFLOW.md` T42): for each
primitive, the claimed property, the security model, whether it is tested, and
whether it is proven. The hand-rolled proxy re-encryption is marked **not
proven** — claiming IND-CPA, unidirectionality, or collusion resistance for a
construction that has not been analysed would be the most serious error the
paper could make.

## Scope honesty

The federation is **simulated** — 2–3 mock facilities with cross-certification.
Say so plainly. Do not imply HIE or FHIR interoperability, which is explicitly
out of scope (`PROJECT.md` §6). Overstating deployment reality is the easiest
kind of dishonesty to fall into and the easiest to catch.

## Citation

Never invent a citation, a figure, an author list, or a venue. If a reference is
needed and not to hand, mark it `\cite{TODO-topic}` and say so, rather than
producing a plausible-looking entry. Fabricated references are the single
fastest way to destroy a paper's credibility, and they are trivially checked.

Quote sparingly and attribute precisely; prefer paraphrase to quotation
throughout.

## Figures

The state diagram and transition table must match the shipped code exactly. When
the implementation changes, the figure changes in the same PR — a paper that
describes a state machine the code does not implement is the failure this rule
prevents.
