# ADR-0024: Deterministic Policy Tree Evaluation Engine (P1-6)

- **Status:** Accepted
- **Date:** 2026-08-24
- **Deciders:** Nandini, Avaneeth, Team
- **Task / source:** P1-6 (WORKFLOW.md); ARCHITECTURE §2 C2, §3; ADR-0002
- **Affects:** `src/policy/stub.py`, `src/policy/exceptions.py`, `src/policy/__init__.py`, `tests/policy/test_policy_stub.py`

## Context

Before cryptographic access (e.g. Shamir secret reconstruction or proxy re-encryption) is invoked, the system must evaluate whether a requester's attributes satisfy the record's access policy tree.

We needed a deterministic, verifiable, and side-effect-free evaluation engine for boolean access trees (`AND`, `OR`, `NOT`, attribute matching) that avoids arbitrary code execution risks (such as `eval()`).

## Decision

1. **Structured AST-Like Node Representation**:
   - Access policies are expressed as deterministic dictionary ASTs composed of:
     - Boolean combinators: `AND`, `OR`, `NOT`
     - Leaf predicates: `ATTRIBUTE_EQ` (`key == target_val`), `ATTRIBUTE_IN` (`target_val in attr_list`), `ALWAYS_ALLOW`, `ALWAYS_DENY`.

2. **Strict Attribute Validation and Deterministic Evaluation**:
   - The engine validates tree structure and rejects unknown operators or malformed schemas with `InvalidPolicyError`.
   - Evaluation resolves strictly boolean results (`True`/`False`) based on request context attributes (e.g. `role`, `facility_id`, `department`, `patient_id`) without dynamic runtime interpretation or external I/O.

## Consequences

- Completely eliminates code injection risks by replacing dynamic script evaluation with a bounded recursive AST walk.
- Auditable: Policy decisions can be logged and re-evaluated deterministically against audit log attributes.
- **Downside**: Complex temporal or rate-limiting expressions cannot be expressed directly in the AST and must be handled at the contract/service layer (e.g., in HSM emergency timers or token expiration checks).

## Alternatives considered

- **Python `eval()` or restricted AST evaluation**: Vulnerable to sandbox escapes and non-deterministic behavior.
- **OPA (Open Policy Agent) / Rego engine**: Introduces an external Go-based binary daemon, violating the pure-Python / lightweight deployment principles.

