# ADR-0043: Key Custodian service and how the portals reach the cryptographic core

- **Status:** Proposed
- **Date:** 2026-09-13
- **Deciders:** Ojas → all four (touches the C16 boundary every ADR since 0014 protects)
- **Task / source:** P4-7, P4-8, P4-8a, P4-9, P4-10 (WORKFLOW.md); the open
  "patient signing-key custody" question in `docs/patient-portal-design.md`;
  ADR-0014, ADR-0021, ADR-0031, ADR-0033
- **Affects:** new `src/api/custodian_service.py` + `custodian_schemas.py`
  (C14), new `src/pre/delivery.py` (C3), `src/audit/events.py` (C10, three
  event types), `deploy/` (sixth process in both paths; `run_portal_demo.py`,
  `seed_portal.py`), `demo/seed_data.py` (keeps issued credentials), the whole
  `portal/` subsystem (C16), ARCHITECTURE.md §7 topology, WORKFLOW.md P4 rows

## Context

Every action the three portals must offer needs a private key or a share on
the caller's side of the wire, and the backend contracts say so explicitly:
`POST /consent/grants` takes an already patient-signed `ConsentGrant`;
`POST /records/{id}/read` takes the holder's attribute keys; `POST
/records/{id}/breakglass` takes a clinician-signed `EmergencyAssertion`, the
clinician's certificate, two threshold shares and a PRE public key. ADR-0014
and ADR-0021 forbid the portal from holding any of that ("the portal holds no
keys" — a standing review item), and the P4-7 design proposal left the
question open with three candidate answers and an instruction not to resolve
it by having the portal hold or forward a key.

Two further gaps surfaced while wiring: consent requests and grants are kept
in each facility process's memory (not in Postgres), so the portal cannot list
them through its read-only store alias; and the clinician's side of break-glass
needs to decode the PRE delivery package, which `breakglass.gate` documents as
"the API layer's job" while CONVENTIONS §2 rule 10 forbids cipher calls in
`api/`.

## Decision

1. **A Key Custodian service** (`custodian`, port 8030) is the sixth federation
   process. It is one process standing in for every subject's personal key
   agent (a smartcard, an enclave or a browser keystore in a real deployment).
   It holds each seeded persona's signing key, certificate, PRE keypair and
   authority-issued credentials, plus each record's clinician-custody share
   (share 1) — all deposited once at seed time, exactly as the audit service is
   handed share 3. It signs consent requests, consent decisions/revocations
   and emergency assertions on a subject's behalf and performs the key-bearing
   federation calls (attribute-key release, `/records/{id}/read`, audit share
   release, `/records/{id}/breakglass`, PRE delivery decode, decryption for
   display, and — for a patient's own upload — the P3-14 ingest: emergency
   key minted and split, share 3 deposited at the audit service, authoring
   keys fetched, `/records/ingest` called). It **decides nothing**: the facility's policy engine, the audit
   service's commit-before-release and the facility's grant-signature check are
   unchanged and still run. No endpoint ever returns a private key.
2. **The portal calls the custodian by `subject_id` after Django login**, and
   calls facilities/audit directly only with bodies that carry no keys (grant
   submission, discovery, emergency search, chain reads, portal-originated
   audit events). A subject with no deposited material gets `404` and nothing
   decrypts — ADR-0021's "a portal account alone grants zero access", now a
   tested HTTP response rather than a convention.
3. **Consent state is mirrored in the portal DB as display/coordination data**
   (`ledger.ConsentRecord`), carrying the *signed public artifacts* (the
   request and the latest grant). The facility remains the only place a grant
   authorises a read; a forged ledger row cannot pass the facility's signature
   check and a ledger row is never consulted by any read path.
4. **Break-glass cases and patient notifications** live in the portal DB
   (`ledger.BreakglassCase`, `ledger.PatientNotification`) for rendering; the
   authoritative record is the audit chain, keyed by the same
   `correlation_id`. Every notification is also appended to the chain as a
   `patient.notification` event (P4-10). Every name+DOB lookup, and every
   selection from its candidates, is appended as `patient.lookup` **before**
   results are shown; if the append fails the results are withheld (P4-8a,
   ADR-0033 rule 5). Consent decisions are appended as `consent.decision`.
5. **`pre.delivery.open_delivery_package`** is the inverse of the gate's step-4
   packaging, homed in the PRE module so the custodian's handler calls a
   domain function, not a cipher.
6. **One correlation id per emergency flow.** The lookup's id is carried into
   discovery, the share release, the re-wrap and the timer's transitions, so
   the admin portal's "trace by correlation id" shows the whole story.

## Consequences

**Commits us to:** a sixth process in both deployment paths (`run_local.py`,
`docker-compose.yml`, TLS cert set); a seed step that deposits key material
(`deploy/seed_portal.py`, driven by `deploy/run_portal_demo.py`, the one-command
portal demo); `demo/seed_data.py` retaining issued credentials and minting a
patient signing keypair; a `ledger` Django app with three models.

**Makes easy:** the whole cross-facility break-glass story is clickable from
a browser, the patient sees the evidence, the auditor traces it by one id, and
the negative tests (no material → nothing; no owner attribute → policy
denial; audit cannot commit → no share, no unlock, state unchanged) run in
process without Postgres.

**Honest downsides:**

- One custodian holding *every* persona's keys is a demo simplification. It
  does not weaken the threshold property (the custodian holds share 1 only; the
  audit service still commits before releasing share 3; the policy engine
  still gates reads), but in a real deployment each subject's agent would be
  their own device. Every key lives in process memory for the custodian's
  lifetime with no eviction and no zeroization (Python cannot reliably wipe an
  immutable key object), so a memory dump of this one process yields every
  deposited key at once. This is the demo's single largest trust concentration.
  The paper's limitations section must say so.
- **The clinician's own signing key never leaves the custodian.** It signs the
  ``EmergencyAssertion`` (and consent artifacts) *inside* the process and only
  the signed public artifact goes upstream. The lifecycle transition at
  break-glass is signed with a *fresh, throwaway* keypair minted per unlock and
  discarded -- the same pattern ``deploy/run_scenario`` and ``demo/driver`` use
  -- because the facility records the actor from the (clinician-signed)
  assertion, not from the transition signature. That throwaway key is still
  transmitted to the facility (P4-1's ``/breakglass`` contract takes
  ``lifecycle_signing_key_pem`` in the body), but it is single-use, carries no
  identity, and its public half is never retained; the facility could equally
  have minted it. Removing even that ephemeral key from the wire would mean the
  facility minting its own transition key -- a change to ``hospital.py``'s
  contract (Avaneeth), worth a later proposal PR, not required for the property
  this ADR protects. A regression test asserts no subject signing key appears
  in any body the custodian sends upstream.
- The custodian trusts the portal's `subject_id`. That is the same trust a
  password manager places in an unlocked desktop session: Django
  authentication is the user's unlock, and ADR-0014/0021 already scope the
  portal to "who is asking". A compromised portal could sign as any seeded
  subject — it still could not read anything the policy tree denies that
  subject, nor open break-glass without the audit commit.
- Share 2 (home authority) is never requested; the demo threshold is met by
  shares 1 + 3, as `deploy/run_scenario.py` and `demo/driver.py` already do.
  The UI shows it as "not requested", not as held.
- P4-1's unlock contract makes the caller supply the re-baseline wrapping key
  for the timer's rotation at expiry. A clinician's agent cannot know a
  record's policy root secret, and since ADR-0040 the facility keeps the
  timer's rotated wrapping in memory only, so the custodian presents a fresh
  random 32-byte placeholder: it lets the time-box register and expire (both
  signed transitions enter the chain), and is discarded with the rotation.
  Re-baseline persistence remains the ADR-0040 gap, now visible from the
  portal as `lifecycle_state` staying `emergency_open` in the store after the
  chain says `expired → granted`. Tracked for P5-4.
- Consent state in two places (ledger mirror + facility memory). The ledger
  is display data and is documented as such; if the facility restarts, its
  grants vanish while the ledger still shows them — a read then fails closed
  at the facility with a signature/lookup error, which the portal renders.

## Alternatives considered

- **Browser-side signing (WebCrypto).** Keys never leave the client — the
  best production answer. Rejected for this project: it would require
  re-implementing every canonical signing payload (`consent.service`,
  `breakglass.assertion`) in JavaScript, which is exactly the "invent a
  construction outside `crypto_core`" the crypto rules forbid, and the holder
  keyring for policy reads would also have to live in the browser.
- **Signing endpoints on the home authority.** Keeps keys server-side but
  turns an attribute authority into a signing oracle for patients and
  clinicians, conflating two trust roles; and the authority never held
  clinician certificate keys or PRE keys in the first place.
- **The portal holding keys in its Postgres schema.** Explicitly ruled out by
  ADR-0014/0021 and the design proposal.
- **Adding consent-listing endpoints to the facility API.** Would remove the
  ledger mirror but requires cross-owner changes to `hospital.py` (Avaneeth)
  and does not solve the in-memory persistence problem; may still be worth a
  proposal PR later.
