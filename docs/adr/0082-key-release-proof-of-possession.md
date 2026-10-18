# ADR-0075: An attribute key is released only to its credential's subject (proof of possession)

- **Status:** Proposed
- **Date:** 2026-10-15
- **Deciders:** Powel (proposal); Ojas (`authority`, custodian, deploy), Avaneeth (`identity`) to review
- **Task / source:** review F15 (D4 decided by ADR-0064, D5 by ADR-0066)
- **Affects:** `authority/possession.py` (`verify_key_release_possession`), `authority/issuance.py` (`credential_binding`, `KEY_RELEASE_OPERATION`), `authority/exceptions.PossessionError`; `api/authority_service.py` (`SubjectTrust`, release route), `api/authority_schemas.py`; `custodian.sign_key_release_possession`, `api/custodian_service.py` (`_holder_keyring`); `identity/subjects.py`; `deploy/asgi/authority.py`, `deploy/run_local.py`, `deploy/docker-compose.yml` (`FACILITY_CA_CERTS_DIR` for authorities); `demo/driver.py`; tests

## Context

`/attribute-keys/release` gave the key to anyone presenting a validly signed
credential. A credential is public signed data, so a copy was enough (F15).
Since ADR-0066 only the custodian and bootstrap may call the route, which
narrows who can try, but anything the custodian is handed still released.

## Decision

A release request carries, besides the credential, a `RequestEnvelope` (the
existing `breakglass.envelopes` construction) that the credential's subject
signed with their own key, and the subject's certificate. The authority:

1. validates the certificate against its configured facility CAs: chain,
   CN = the credential's `subject_id`, role patient or clinician (not a
   service), not revoked;
2. checks the envelope is from that subject, addressed to this authority,
   for `attribute_key.release`, over the credential's canonical bytes, and
   recent;
3. verifies the signature and consumes the one-time `request_id`;

and only then checks the credential and releases the key. The custodian signs
the envelope in `custodian.sign_key_release_possession`; a subject without a
certificate gets no keys. An authority with no facility CAs configured
releases nothing (503).

## Consequences

- A copied credential alone, or one presented with someone else's signature,
  releases nothing; a captured release request cannot be replayed (claim
  C10, mutation C10b).
- Authorities now need `FACILITY_CA_CERTS_DIR` (set in `run_local` and
  Compose; the `pki` job already writes it before they start).
- The custodian holds every subject's key (ADR-0043), so this does not
  constrain the custodian itself. That trust is stated in ADR-0043 and
  PROJECT.md §5 caveat 5.
- Releases are not audited at the authority; that is unchanged.

## Alternatives considered

- **Bind the credential to a key at issuance and check a signature over a
  challenge.** Needs a challenge round-trip and a contract change; the
  envelope gives the same proof in one request with existing code.
- **Rely on ADR-0066's caller restriction only.** Leaves the custodian
  exchanging any credential it is given.
