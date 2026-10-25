# 4. Who can read what: policy tree, consent, portals

*Paper: Section V-D (Access Structure), Section III (assets and adversaries),
Section IV (what portals and Postgres may not do).*

**One-paragraph version.** A record's key is locked behind a *policy tree* of
attributes (for example "physician AND endocrinology"). A doctor who holds the
matching attribute keys can rebuild the key; one who does not, cannot. A
patient-signed **consent grant** is checked at read time when one is presented.
And the web portals only show data: they never decide anything.

## The policy tree (our substitute for CP-ABE)

Real attribute-based encryption needs pairing libraries that are painful to
install, so we rejected it (ADR-0001) and built a hand-rolled access structure
over Shamir sharing (ADR-0002, ADR-0026).

```
rec-002 policy:      OR
                    /    \
                  AND     owner:pat-102   <- patient self-access leaf
                 /   \                       (home authority's attribute)
   role:physician   specialty:endocrinology
   (authority-med)  (authority-net)
```

- A policy is a tree of **Leaf, And and Or** nodes. There is **no general k-of-n
  gate**.
- It is **compiled top-down from a fresh 32-byte root secret**:
  - an **And** node with m children Shamir-splits its incoming secret **m-of-m**;
  - an **Or** node passes the **same secret** to every child;
  - a **leaf** encrypts its incoming secret with AES-256-GCM under an **attribute
    key**.
- **The root secret is the DEK wrapping key.** The wrapping's associated data
  binds the **record id, policy id and generation**, so a wrapping cannot be moved
  to another record or replayed as another generation.
- **Attribute keys** are symmetric 32-byte keys indexed by
  **(authority, attribute name, value)**. The same `name:value` from another
  authority does **not** open the leaf.
- **Every record's tree is `Or(clinical policy, owner:patient)`**, where the owner
  leaf belongs to the patient's home authority (ADR-0016). The patient reads their
  own record through the same reconstruction path as a doctor. No back door.
- **Reconstruction runs bottom-up** and raises `PolicyDeniedError` if the root is
  unsatisfied. It never returns a partial or default secret.

**Say plainly (limit 4):** *this is not full CP-ABE.* It is **not
collusion-resistant**: two clinicians can pool attribute keys to satisfy a policy
neither satisfies alone, which pairing-based CP-ABE prevents. It has **no security
proof**. Two further consequences:

- **Leaf ciphertexts carry no associated data**, so they are not bound to their
  record, position or attribute. Only the DEK wrapping is bound.
- Attribute keys are **shared by every holder and never rotated** (limit 9), so
  revoking a credential stops *future releases* but does not take back a key
  already held.

## The screenshot: why `house` was refused on `rec-002`

Dr. Rao holds `role:emergency-physician` and `specialty:emergency-medicine`.
`rec-002` needs `physician` AND `endocrinology`. The patient's consent was
granted, but the policy tree still said no, so nothing was decrypted and the
denial went into the chain. That is the intended demo of **"consent is necessary,
not sufficient"**.

## Consent (ADR-0031, ADR-0017)

- The patient **signs a grant** (scope = record ids, grantee, expiry, status).
  When a grant is presented, the facility checks **status, time window and
  signature**, plus grantee and scope, **before** running the crypto path.
- A grant **only records intent**; it never releases a key.
- Revocation of the grant is a **fresh patient-signed REVOKED grant**, which the
  facility then refuses. Only the patient's key makes a valid one.
- **Consent is *not* a lifecycle state.** It does not move the record's state, and
  the consent module never wraps or re-wraps records (paper Section V-A). The
  portal's mirrored consent rows are display data that no read path consults.

(Revoking *access to the record* is a different thing: that is the lifecycle
Granted→Revoked transition with a full key rotation; see file 2.)

## Patient self-access (ADR-0016) and claim C11

The patient reads their own record through an `owner:<patient_id>` attribute
issued only by the **home authority**. If that attribute is absent, the read fails
closed. **Claim C11: a patient login alone never releases a DEK**: the custodian
refuses a patient without an owner credential.

Threat-model footnote: a **rogue home authority** can mint that patient's `owner`
key, so protection against it is *partial*.

## The portals and the Key Custodian

```
 browser --> Django portal (who are you?) --> Key Custodian (signs / presents)
                |                                   |
                | DB roles cannot write          facility / audit / authorities
                v  store tables                  decide: policy tree + threshold
          Postgres: ciphertext only
```

- The portals **identify people and show data.** The portal holds **no subject
  key** and sends every key-needing action to the custodian by subject id, so a
  portal account alone decrypts nothing (claim C11). The portal's database roles
  cannot write store tables (ADR-0014).
- The **custodian** is one process acting as every persona's key agent. It holds
  every synthetic persona's signing key, PRE key, credentials and share 1, and
  signs on their behalf after portal login. In reality each agent would be the
  person's own device or enclave (limit 5, ADR-0043).
- **Caveats the paper states:** the federation services connect to Postgres as the
  `postgres` superuser (only the portal is role-restricted), and the HTTP TLS
  certificates are self-signed and server-only.
- **Service calls are authenticated** (ADR-0066): every call carries a
  root-issued service certificate and a signed one-time request envelope, checked
  before any route code runs, and key-bearing facility routes admit only the
  custodian or bootstrap (claim C9, BOLA).

## Emergency identification (ADR-0033, ADR-0085)

The clinician finds the patient by **family name + date of birth** in the portal's
directory. Ambiguous matches are shown as a list and the clinician must choose; the
portal never picks. **Every lookup, hit or miss, is logged first.** The chain holds
the pseudonymous `patient_id`, **not the name or date of birth** (ADR-0085).
Identifying someone releases **no key**.

**Limit 7:** a patient with no ID gets only a temporary encounter id until staff
confirm identity, so the scenario assumes identification, which a real emergency
department often lacks.

## Where to point in the code

`src/policy/engine.py` (compile and reconstruct), `src/consent/`,
`portal/clinician/views.py`, `portal/portal_core/services.py`,
`src/api/custodian_service.py`. Demo personas: `demo/seed_data.py`.
