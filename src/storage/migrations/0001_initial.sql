-- P0-8 initial schema for the shared encrypted store (C4).
--
-- Boundary (ADR-0014 / ADR-0011): this store PERSISTS ciphertext, wrapped keys,
-- and identifiers. It holds no key material in the clear, no plaintext, and it
-- NEVER decides access -- keys and the Shamir threshold gate do that. Foreign
-- keys enforce referential integrity only, never authorization.
--
-- Columns mirror the frozen contracts in src/contracts/: identifiers -> text,
-- crypto material (ciphertext, wrapped DEKs, nonces, signatures, hashes) ->
-- bytea, timestamps -> timestamptz, enums -> text + CHECK. No plaintext columns.

-- Attribute authorities (medical board, health network). Public params only.
CREATE TABLE authorities (
    authority_id text PRIMARY KEY,
    display_name text NOT NULL,
    public_key   bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Federation facility nodes (mirrors the Facility contract).
CREATE TABLE facilities (
    facility_id  text PRIMARY KEY,
    display_name text NOT NULL,
    endpoint     text NOT NULL,
    public_key   bytea NOT NULL,
    status       text NOT NULL
        CHECK (status IN ('active', 'suspended', 'decommissioned'))
);

-- Patients: identifiers only. No names or PHI here -- patient PII lives in the
-- portal DB, never in the crypto store. home_authority_id is the patient's home
-- authority (ADR-0019), which issues their owner:* key and holds break-glass
-- share 2.
CREATE TABLE patients (
    patient_id       text PRIMARY KEY,
    home_authority_id text NOT NULL REFERENCES authorities (authority_id),
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- Attribute registry: which authority owns which name:value attribute.
-- NOTE: minimal placeholder -- refine when `authority` (C6) lands (P2-2); the
-- frozen contracts define AttributeCredential (held by clinicians), not a
-- storage shape for attribute ownership.
CREATE TABLE attributes (
    authority_id text NOT NULL REFERENCES authorities (authority_id),
    name         text NOT NULL,
    value        text NOT NULL,
    PRIMARY KEY (authority_id, name, value)
);

-- Encrypted health records (mirrors the Record contract). ciphertext is
-- AES-256-GCM output; the store never decrypts it. policy_id references the
-- access policy governing decryption.
-- NOTE: there is no `policies` table in the ARCHITECTURE §2 C4 list, so
-- policy_id is not a foreign key here; policy-tree storage lands with `policy`
-- (C7, P2-3).
CREATE TABLE records (
    record_id    text PRIMARY KEY,
    patient_id   text NOT NULL REFERENCES patients (patient_id),
    facility_id  text NOT NULL REFERENCES facilities (facility_id),
    policy_id    text NOT NULL,
    content_type text NOT NULL,
    ciphertext   bytea NOT NULL,
    nonce        bytea NOT NULL CHECK (octet_length(nonce) = 12),
    aad          bytea,
    created_at   timestamptz NOT NULL
);

-- Wrapped DEKs (mirrors the DEKWrapping contract). One record's DEK sealed under
-- a wrapping key, once per authorised party; generation increments on re-wrap.
CREATE TABLE dek_wrappings (
    wrapping_id text PRIMARY KEY,
    record_id   text NOT NULL REFERENCES records (record_id),
    wrapped_for text NOT NULL,
    wrapped_dek bytea NOT NULL,
    nonce       bytea NOT NULL CHECK (octet_length(nonce) = 12),
    generation  integer NOT NULL CHECK (generation >= 0),
    created_at  timestamptz NOT NULL,
    UNIQUE (record_id, wrapped_for, generation)
);

-- Current lifecycle state per record (the four-state machine, C9).
CREATE TABLE lifecycle_state (
    record_id     text PRIMARY KEY REFERENCES records (record_id),
    state         text NOT NULL
        CHECK (state IN ('granted', 'revoked', 'emergency_open', 'expired')),
    last_event_id uuid,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Signed lifecycle transitions (mirrors the TransitionEvent contract).
CREATE TABLE transition_events (
    event_id    uuid PRIMARY KEY,
    record_id   text NOT NULL REFERENCES records (record_id),
    from_state  text NOT NULL
        CHECK (from_state IN ('granted', 'revoked', 'emergency_open', 'expired')),
    to_state    text NOT NULL
        CHECK (to_state IN ('granted', 'revoked', 'emergency_open', 'expired')),
    actor_id    text NOT NULL,
    reason_code text,
    issued_at   timestamptz NOT NULL,
    nonce       bytea NOT NULL CHECK (octet_length(nonce) >= 16),
    signature   bytea NOT NULL CHECK (octet_length(signature) > 0)
);

-- Hash-chained signed audit log (mirrors the AuditEntry contract). recorded_at
-- carries the contract's `timestamp` field (renamed to avoid the SQL keyword).
CREATE TABLE audit_log (
    seq         bigint PRIMARY KEY,
    prev_hash   bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash  bytea NOT NULL CHECK (octet_length(entry_hash) = 32),
    event_type  text NOT NULL,
    event_data  jsonb NOT NULL,
    actor_id    text NOT NULL,
    correlation_id text NOT NULL,   -- groups all entries of one flow (ADR-0017)
    recorded_at timestamptz NOT NULL,
    signature   bytea NOT NULL CHECK (octet_length(signature) > 0)
);

-- Coded search index (C12). coded_term is opaque -- the store cannot read it.
-- NOTE: minimal placeholder -- refine when `search` (C12) lands (P3-8); no
-- frozen contract defines the coded-index shape yet.
CREATE TABLE search_index (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    record_id  text NOT NULL REFERENCES records (record_id),
    coded_term bytea NOT NULL
);
