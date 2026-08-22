# ADR-0019: Federation instantiated at two facilities; attribute-authority ownership

- **Status:** Accepted
- **Date:** 2026-08-21
- **Deciders:** Powel (P0-7 owner), confirmed with the team
- **Task / source:** P0-7 (WORKFLOW.md); ARCHITECTURE.md §7; ADR-0016
- **Affects:** `identity` (C5), `authority` (C6), `policy` (C7), deploy/demo; [docs/federation-topology.md](../federation-topology.md)

## Context

P0-7 asks us to fix the concrete make-believe federation: how many facilities and
authorities, which authority owns which attributes, and one trust root. Two
existing docs disagreed on the facility count:

- **ARCHITECTURE.md §7** commits to a **six-process** topology with exactly two
  facilities (`facility-a`, `facility-b`), and its bootstrap and deploy paths say
  "both facilities."
- **WORKFLOW.md P0-7** said "three hospitals."
- **PROJECT.md §6** allows "2–3 mock facilities."

The attribute-authority split was partly fixed (§7: `authority-med` owns `role:*`;
`authority-net` owns `specialty:*`, `facility:*`) but `owner:*` — added by ADR-0016
for patient self-access — had no assigned owner, and the "patient home authority"
that holds break-glass Share 2 (ARCHITECTURE §5) was not bound to a concrete
service.

## Decision

1. **Two facilities, matching ARCHITECTURE §7** — `facility-a` (patient home) and
   `facility-b` (out-of-network emergency entry point). WORKFLOW P0-7's "three
   hospitals" is reconciled down to two; the break-glass demo scenario needs only
   these two, and a third process buys no novelty. Ports and process set are §7's,
   unchanged (`store` 8000, `facility-a` 8001, `facility-b` 8002, `authority-med`
   8010, `authority-net` 8011, `audit` 8020).
2. **Attribute-namespace ownership** is frozen for P0-7 as:
   - `authority-med` (State Medical Board) owns **`role:*`**.
   - `authority-net` (Regional Health Network) owns **`specialty:*`**, **`facility:*`**,
     and **`owner:*`**.
3. **`authority-net` is the patient home authority**: it issues each patient's
   `owner:<patient_id>` attribute (ADR-0016) and holds **break-glass Share 2**
   (ARCHITECTURE §5). One service plays both roles so "the patient's home
   authority" is a concrete process, not an abstraction.

## Consequences

- Phase 2 (`identity`, `authority`, `policy`) and Phase 4 (deploy, demo) get
  concrete names, ports, and an ownership matrix to code and test against, all
  consistent with §7.
- WORKFLOW P0-7 is edited to say "two hospitals"; no ARCHITECTURE change is needed
  because §7 already said two.
- **Trust concentration (carried from threat-model §5).** Making `authority-net`
  both the `owner:*` issuer and the Share-2 holder concentrates two sensitive
  roles in one service: a rogue `authority-net` could mint a patient's `owner`
  key *and* contribute Share 2. It still cannot break glass alone (needs 2 of 3),
  and it was already the Share-2 holder, so this adds no new trusted party — but
  it is the widest single-authority exposure and is listed as such.
- No new attribute namespaces are introduced (no `dept:*`); departments remain
  portal metadata, never a crypto attribute, keeping the authority matrix to what
  §7 and ADR-0016 already require.

## Alternatives considered

- **Three facilities (add `facility-c`).** Rejected: contradicts §7's six-process
  topology and "both facilities" bootstrap, adds a seventh process and demo
  surface, and adds nothing to the novelty. PROJECT §6's "2–3" permits two.
- **`owner:*` owned by `authority-med`.** Rejected: the home authority already
  holds Share 2 at `authority-net`; splitting `owner:*` to `authority-med` would
  put a patient's self-access key at a service that is not their home authority,
  contradicting ADR-0016's "issued and held by the patient's home authority."
- **A separate dedicated home-authority service.** Rejected for now: a seventh
  process for a role `authority-net` can already carry; revisit only if the
  trust-concentration consequence above proves to matter for the paper.
