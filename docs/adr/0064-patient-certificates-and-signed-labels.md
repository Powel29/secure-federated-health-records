# ADR-0064: Patient certificates, patient-signed clinical labels, certified consent keys

- **Status:** Proposed
- **Date:** 2026-10-14
- **Deciders:** Powel (proposal, `crypto_core`); Avaneeth (`identity`, `records`, `api`, PR #40), Ojas (custodian, deploy), Nandini (portal) to review; `src/contracts/` change needs all four
- **Task / source:** PR #40 review findings 1, 3 and 14; review of PR #40's clinical metadata
- **Affects:** `crypto_core.build_certificate` (optional subject OU) and `certificate_role`; `identity` (`issue_patient_certificate`, `validate_patient_certificate`, `PatientCertificateError`); `contracts.clinical.ClinicalMetadata` (`signature`, `signer_certificate_pem`); new `records/labels.py`; `api/hospital.py` (read gate, consent verification, break-glass requirements, ingest); `api/custodian_service.py` (signs labels at upload, presents patient certificates); `api/schemas.py` and `api/custodian_schemas.py` (`patient_certificate_pem` replaces `patient_public_key_pem`); portal consent calls; demo and portal seeds; ADR-0060, ADR-0062

## Context

PR #40 stores each record's clinical labels (title, author, source, sensitivity,
care-team consent flag) as a plain `jsonb` column in the shared store, and the
facility decides from them whether break-glass needs a written justification and
whether a clinician read needs the patient's consent. Nothing authenticated the
column, so a store write could loosen the rules: change `hiv` to `general` and
the restricted-record justification is no longer asked for. CLAUDE.md says the
store never decides access.

A patient signature over the labels would fix that only if the facility knew the
patient's key. It did not: patients had no certificates, and the consent path
already verified grants against a `patient_public_key_pem` the caller sent in
the same request, so anyone could sign with their own key and send it.

## Decision

1. **Patient certificates.** A patient's home facility CA certifies their key,
   the same issuance path as a clinician's. The certificate carries OU
   `patient`; a clinician certificate carries none, so neither stands in for
   the other. `identity.validate_patient_certificate` checks the chain to the
   configured root, the role, the subject (= patient id) and revocation.
2. **Signed labels.** The custodian signs every record's labels with the
   patient's key at upload (patient uploads and clinician notes alike) and
   attaches the certificate. The signed bytes are a JSON array of a domain tag,
   the record id, the patient id and every label, so labels cannot be moved to
   another record or shifted between fields. This is the project's existing
   ECDSA signing over canonical bytes; no new construction.
3. **Strictest unless verified.** `records.labels.disclosure_rules` trusts the
   labels only when the signature verifies against a configured CA. Unsigned
   labels, a bad signature, a non-patient certificate or labels from another
   record all get every requirement: both break-glass justifications and a
   patient grant for clinician reads. Removing or editing labels can only make
   access harder. A bad signature is logged and treated as strictest rather
   than refused, so a tampered row cannot block emergency care.
4. **Certified consent keys.** Consent grants (read path and grant submission)
   are verified against the key in a patient certificate the facility validates,
   never against a caller-supplied key. `patient_certificate_pem` replaces
   `patient_public_key_pem`; the old field is now rejected.
5. Ingest verifies signed labels when present and refuses ones that do not
   verify; unsigned labels are stored and get the strictest rules.

## Consequences

- Closes PR #40 review findings 1 and 3 (labels can be swapped; the store
  decides reads) and the older consent-key weakness (finding 14). Negative
  tests in `tests/security/test_patient_certificates.py`, each observed failing
  with its control removed.
- Every path that creates records must sign labels, or those records get the
  strictest rules. The demo seed, portal seed, custodian and test fixtures sign;
  `bench/run_benchmarks.py` was already incompatible with PR #40's
  justification rule and is unchanged.
- Self-registered patients still get no certificate (issuance is unwired,
  ADR-0021), so their uploads are unsigned and strictest.
- **Not fixed: confidentiality.** Titles and sensitivity labels are still
  readable in the store and shown at discovery (finding 2). This protects
  integrity only; see the honest-limits explainer.
- The custodian signs as the patient for clinician notes too: it stands in for
  every persona's device (ADR-0043), so the patient-device-signs model holds
  only as far as that simplification does.
- `src/contracts/` changes (`ClinicalMetadata` fields) need the all-four
  contract approval PR #40 needs anyway.

## Alternatives considered

- **Home facility signs the labels with a facility signing key** — also fixes
  integrity, but needs a new long-lived facility key in bootstrap and leaves the
  consent-key weakness open.
- **Bind the labels into the record's GCM AAD** — detects tampering only at
  decryption, after break-glass has already released the DEK.
- **Treat unsigned labels as legacy (the pre-PR-40 rules)** — less churn, but
  stripping a signature would downgrade a record, so the swap attack would
  stay open.
- **Document the gap only** — rejected in favour of fixing integrity now.
