# ADR-0024: Cross-certification via a single shared root, not a peer CA mesh

- **Status:** Accepted
- **Date:** 2026-08-30
- **Deciders:** Avaneeth (P2-1/P2-2 owner)
- **Task / source:** P2-1, P2-2 (WORKFLOW.md); ARCHITECTURE.md §2 C5/C6, §7 step 2; ADR-0019
- **Affects:** `identity` (C5), `authority` (C6)

## Context

P2-1 asks for "cross-certification so an out-of-network doctor can be
verified," and ARCHITECTURE.md §7 step 2 says "issue facility CA certificates
signed by the anchor; cross-certify the facilities so `facility-b` can
validate a clinician enrolled at `facility-a`." "Cross-certification" is a
PKI term that more commonly names a *mesh*: each CA independently signs a
certificate for every other CA it wants to trust, so trust exists without one
shared party. ADR-0019 had already fixed "one shared trust root" for the
federation, but the implementation had not yet decided which of the two
cross-certification shapes that root implies.

Two readings were possible for how `identity` (C5) implements this:

1. **Hierarchical, single-root.** Every facility CA and every attribute
   authority is issued a certificate by the one shared root
   (`generate_root_anchor`). `facility-b` validates a `facility-a` clinician
   by walking the chain clinician -> facility-a CA -> root, trusting the root
   it already has -- no direct relationship with facility-a's CA is needed.
2. **Peer mesh.** Each facility CA is self-signed (or root-signed) *and*
   additionally cross-signs every other facility's CA certificate directly,
   independent of any shared root.

## Decision

Adopt **(1), hierarchical single-root trust**, implemented as:
`identity.root_anchor.generate_root_anchor` issues the one self-signed root;
`identity.certificates.issue_facility_ca_certificate` /
`issue_authority_certificate` /`issue_clinician_certificate` each issue a
certificate signed by their parent in that hierarchy; `identity.chain`
validates a presented certificate by walking up to a caller-supplied
`trusted_root` and failing closed on any broken link (bad signature, expired
window, non-CA intermediate, or issuer/subject mismatch);
`identity.trust_registry.TrustRegistry` is what a facility node consults --
it refuses to register a facility CA that doesn't itself chain to the
registry's root.

## Consequences

- **"Cross-certify the facilities" becomes one step, not N².** Because both
  facilities' CAs are signed by the same root, any facility that already
  trusts the root transitively trusts every other facility's clinicians with
  no additional pairwise signing step. This is cheaper to implement, cheaper
  to reason about in the viva, and matches ADR-0019's "one shared trust root"
  decision exactly -- a mesh would have made that ADR's "one root" language
  misleading.
- **Attribute authorities reuse the same mechanism.** `C6 authority <- C5`
  (ARCHITECTURE.md §4: "issuance needs certs to sign under") is satisfied by
  giving each authority a root-issued certificate too
  (`authority.certification.certify_authority`), so an authority's signing
  key is itself verifiable, not merely asserted.
- **Honest downside -- single point of trust.** Every certificate in the
  federation is only as trustworthy as the one root key. A compromised root
  invalidates the whole PKI at once, which a peer mesh (no single shared
  secret) would not. This is judged acceptable for a course project with one
  simulated federation and is the same trade-off ADR-0019 already made at the
  topology level; recorded here again because it is now baked into working
  code, not just a topology diagram.
- **Chain validation must reject a self-consistent-but-wrong root**, not just
  a broken signature. `identity.chain.validate_chain` takes an explicit
  `trusted_root` argument and verifies the top-of-chain signature against
  *that* root's actual public key -- an attacker who runs their own private
  root and forges a plausible chain is still rejected, because the caller
  never passes the attacker's root as `trusted_root` (tested in
  `tests/security/test_phase2_security.py::test_sec_forged_certificate_rejected_by_a_different_root`).

## Alternatives considered

- **Peer CA mesh (option 2).** Rejected: contradicts ADR-0019's "one shared
  trust root," adds O(facilities²) cross-signing bookkeeping for no benefit
  at a two-facility scale, and gives the paper a harder story to explain for
  no corresponding security gain in this threat model.
- **Namespace enforcement left unchecked at issuance.** Considered leaving
  `authority.issue_credential` trust the caller to only request attributes it
  owns. Rejected: ADR-0019 assigns attribute namespaces per authority
  specifically so no one authority can mint any attribute; not enforcing it
  in code would make that assignment a comment, not a control. Implemented
  as `AttributeAuthority.owned_attribute_names`, checked before every
  issuance, raising `UnauthorizedAttributeError` otherwise.
