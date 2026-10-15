# ADR-0069: Expiry runs a full rotation -- new DEK, policy root, emergency key and shares, search index

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (decision, review D3-a; owns `lifecycle`); Avaneeth (`api`, `storage`, `records`), Nandini (`search`), Ojas (custodian, audit share custody) to review
- **Task / source:** review D3 / F9 (claim C4); ARCHITECTURE.md §5 step 7
- **Affects:** new `lifecycle/rotation.py` (`plan_rotation`), `api/rotation.py` (`FacilityRotator`, `http_rotation_ports`); `lifecycle/expiry.py` (rotator hook, no baseline key); `policy.engine.policy_tree_of`, `policy_leaves`; `search.service` (`seal_search_terms`, `open_search_terms`); `records/ingest.py` (sealed terms); `api/repository.py` (`apply_rotation`, sealed terms); `storage` (migration 0005 `record_search_terms`, `rotate_record_ciphertext`); `audit.share_registry.replace`, `PUT /breakglass/shares/{id}`; custodian `PUT /records/{id}/shares`; `api/schemas.py` (`baseline_wrapping_key_b64` removed); ADR-0035, ADR-0040, ADR-0047

## Context

Expiry computed a rotated record and wrapping and threw both away; the
custodian sent a random "baseline key" that was not a key to anything. The old
shares, the emergency wrapping and the search tokens all kept working after
the window closed (F9), so "search tokens are dead because the key they derive
from is gone" (§5 step 7, C4) was false.

## Decision

At expiry, between the signed `EMERGENCY_OPEN -> EXPIRED` and
`EXPIRED -> GRANTED/REVOKED` transitions, the facility's rotator:

1. reads the record's access tree back from its compiled policy and fetches an
   authoring key per leaf from the owning authority (signed request, ADR-0066);
2. computes, once, a `RotationPlan` (`lifecycle.rotation.plan_rotation`):
   a fresh DEK and re-encrypted record under a new policy id; the same tree
   compiled under a fresh root secret, the new DEK wrapped under it
   (generation + 1); a fresh emergency key split 2-of-3 with the new DEK
   wrapped under it (generation + 1); the record's search terms re-derived
   under the new emergency key;
3. stores it in one transaction (`apply_rotation`, a compare-and-set on the
   record's ciphertext nonce, idempotent on retry);
4. hands the new share 1 to the custodian and share 3 to the audit service.
   Each holder replaces its share only for a facility caller, only while the
   shared store shows the record `expired`, and only for the next generation
   (a retry of the same share is a no-op).

**Search terms are stored locked** (user decision): at ingest the term list is
sealed with AES-256-GCM under the record's own DEK with a domain-separated AAD
(`health-record-search-terms-v1:<record_id>`) and kept in
`record_search_terms`; rotation opens it with the old DEK and seals it under
the new one. Every step reuses the module that built the same artefact at
ingest; no new construction.

The plan lives on the session, so a retry after a failure finishes the same
rotation rather than minting a second key whose shares would not match ones
already handed out. The record returns to baseline only after both holders
have the new shares; a manager without a rotator never returns a record to
baseline, and a facility without rotation ports refuses break-glass (503).

## Consequences

- C4 holds: after expiry the old shares open nothing, the old token finds
  nothing, and the holders' new shares open the record with search working
  (`test_c4_pre_expiry_shares_do_not_restore_search`); mutation C4b (rotation
  skipped) turns it red. Live over sockets on Postgres:
  `tests/deploy/test_end_to_end.py` waits for the rotation and finds a
  generation-1 emergency wrapping.
- Scripts that hold share 1 themselves (demo, scenario, bench) now deposit it
  with the custodian too, or rotation would be refused.
- Each expiry costs one authoring call per policy leaf, two share deposits and
  one transaction; the record's policy id changes at every rotation.
- **Residual risks, stated plainly:**
  - A facility restart mid-expiry loses the in-memory plan (F5/D7, ADR-0050):
    if it dies after the store commit but before both deposits, no holder set
    matches the stored emergency wrapping and break-glass for that record is
    impossible until it is re-provisioned. Access stays closed, never open.
  - A compromised facility can replace a record's shares during that record's
    `expired` window (the holders check kind, state and generation, not which
    facility ran the session).
  - Plaintext a clinician already decrypted is not retractable (ADR-0035).
  - Share 2 is still generated and discarded (D2).
  - Anyone holding the DEK can open the sealed term list; deterministic
    search-token leakage (ADR-0027) is unchanged.

## Alternatives considered

- **D3-b: rotate the emergency path only** (new emergency key, shares and
  search tokens; DEK unchanged) -- smaller, but the pre-expiry DEK keeps
  opening the record, which the user rejected.
- **Re-supply search terms from the patient** -- an unconscious patient cannot,
  and search would stay dead until they did.
- **Drop the search index at expiry** -- kills C12 for every later emergency.
- **Deposit shares before storing** -- same failure profile on a crash, but
  leaves a window where the holders' shares open nothing the store holds.
