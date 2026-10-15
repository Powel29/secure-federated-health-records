-- Service authentication, audit-side assertion checks and rotation at expiry.
--
-- release_assertion (ADR-0067): the audit service consumes each emergency
-- assertion it validates before releasing share 3. The facility consumes the
-- same assertion id under 'assertion', so the two holders need separate kinds
-- in this shared table. Request envelopes (ADR-0066) already use 'request'.
ALTER TABLE consumed_ids DROP CONSTRAINT consumed_ids_kind_check;
ALTER TABLE consumed_ids ADD CONSTRAINT consumed_ids_kind_check
    CHECK (kind IN ('assertion', 'request', 'transition_event', 'release_assertion'));

-- A record's search terms, sealed with AES-256-GCM under the record's own DEK
-- (ADR-0069), so expiry can rebuild the search index under a new emergency
-- key. Ciphertext only; the store cannot read the terms.
CREATE TABLE record_search_terms (
    record_id  text PRIMARY KEY REFERENCES records (record_id),
    ciphertext bytea NOT NULL,
    nonce      bytea NOT NULL CHECK (octet_length(nonce) = 12)
);
