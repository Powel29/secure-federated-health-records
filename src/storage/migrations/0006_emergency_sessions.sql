-- Open emergency sessions (ADR-0081, review F5): one row per break-glass
-- window, written when it opens and deleted when its expiry has finished.
-- A facility that restarts finds its own rows here and finishes them: the
-- emergency key died with the old process, so the record is closed and
-- rotated rather than left open. No key material: identifiers, the state
-- the record returns to, and times only.
CREATE TABLE emergency_sessions (
    record_id          text PRIMARY KEY REFERENCES records (record_id),
    facility_id        text NOT NULL,
    return_state       text NOT NULL CHECK (return_state IN ('granted', 'revoked')),
    actor_id           text NOT NULL,
    correlation_id     text NOT NULL,
    opener_facility_id text NOT NULL,
    opened_at          timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL
);
CREATE INDEX emergency_sessions_facility ON emergency_sessions (facility_id);
