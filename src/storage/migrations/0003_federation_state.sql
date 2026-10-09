-- Encrypted policy layouts and signed consent artifacts must be shared by
-- separate facility processes. No plaintext keys or unencrypted shares here.
CREATE TABLE compiled_policies (
    policy_id text PRIMARY KEY,
    payload jsonb NOT NULL
);
CREATE TABLE consent_requests (
    request_id uuid PRIMARY KEY,
    payload jsonb NOT NULL
);
CREATE TABLE consent_grants (
    grant_id uuid PRIMARY KEY,
    patient_id text NOT NULL,
    payload jsonb NOT NULL
);
CREATE INDEX consent_grants_patient ON consent_grants (patient_id);

-- Written only after seeding and audit verification have both succeeded.
CREATE TABLE deployment_bootstrap (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    instances jsonb NOT NULL,
    seeded boolean NOT NULL
);
