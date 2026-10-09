# 4. Who can read what: policy tree, consent, portals

**One-paragraph version.** A record's key is locked behind a *policy tree* of
attributes (for example "physician AND endocrinology"). A doctor who holds the
matching attribute keys can rebuild the key; one who does not, cannot. Patient
consent is a separate gate in front of that. And the web portals only show
data: they never decide anything.

## The policy tree (our substitute for CP-ABE)

Real attribute-based encryption needs pairing libraries that are painful to
install, so we rejected it (ADR-0001) and built the same effect with Shamir
sharing (ADR-0002, ADR-0026).

```
rec-002 policy:           AND
                         /   \
        role:physician        specialty:endocrinology
        (authority-med)       (authority-net)
```

- Each **leaf** (an attribute) has a share encrypted under that attribute's key,
  issued by the authority that owns the attribute.
- **AND** node: the parent's secret is split k-of-k, so every child is needed.
- **OR** node: every child gets the same secret, so any one is enough.
- The root secret wraps the record's data key.

A clinician holding `role:physician` and `specialty:endocrinology` rebuilds the
root and opens the record. Holding only one of them gives a mathematically
useless share. No per-doctor setup is needed, and attributes come from
**independent authorities**, which is what cross-hospital access needs.

**Honest limit:** two doctors could pool their attribute keys and satisfy a
policy neither meets alone. Real pairing-based CP-ABE prevents that; ours does
not. It is in the paper's limitations and real CP-ABE is a stretch goal.

## The screenshot you saw: why `house` was refused on `rec-002`

Dr. House holds `role:emergency-physician` and `specialty:emergency-medicine`.
`rec-002` needs `physician` AND `endocrinology`. The patient's consent was
granted, but the policy tree still said no, so nothing was decrypted and the
denial went into the chain. This is the intended demo of **"consent is
necessary, not sufficient"**.

## Consent is a gate on top (ADR-0031)

The patient signs a grant (scope, expiry, grantee). The facility verifies the
signature and checks the grant **before** running the crypto path. A grant only
records intent. It never releases a key by itself. Revocation by the patient
is a fresh signed REVOKED grant, which the facility then refuses.

## Patient self-access (ADR-0016)

Every record's policy is `OR(clinical policy, owner:<patient_id>)`. The patient
reads their own record through the very same reconstruction path, using an
`owner:` attribute held by their home authority. If that attribute is absent,
the read fails closed. Logging into the portal alone releases nothing.

## The portals and the Key Custodian

```
 browser --> Django portal (who are you?) --> Key Custodian (signs / presents)
                |                                   |
                | read-only DB role              facility / audit / authorities
                v                                   decide: policy tree + threshold
          Postgres: ciphertext only
```

- The portals identify people and show data. The database role the portals use
  is **read-only** (`portal_ro`), so the boundary is enforced by Postgres, not
  by good manners.
- The custodian is a single process that holds every *demo* persona's keys and
  signs on their behalf after login. In a real deployment each person would hold
  their own keys on their own device. Say this plainly (ADR-0043).
- Even a fully compromised portal could not read anything the policy tree denies
  that person, nor open break-glass without the audit commit.

## Emergency identification (ADR-0033)

The clinician finds the patient by **family name + date of birth** in the
portal's directory. Ambiguous matches (two "Alice Vance, 1982-04-15") are shown
as a list and the clinician must choose; the portal never picks. Every lookup,
hit or miss, is written to the audit chain first. Identifying someone releases
no key.

## Where to point in the code

`src/policy/engine.py` (compile and reconstruct), `src/consent/`,
`portal/clinician/views.py`, `portal_core/services.py`. Demo personas are in
`demo/seed_data.py`.
