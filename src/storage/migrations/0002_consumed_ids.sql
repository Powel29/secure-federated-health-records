-- One-time ids that must survive a process restart (review F22).
--
-- Emergency assertions, request envelopes and lifecycle transition events each
-- carry a one-time id. Holding the consumed set only in process memory lets a
-- restart re-open replay for any id that is still otherwise valid. A primary
-- key on (kind, id) makes "consume" a single INSERT ... ON CONFLICT DO NOTHING:
-- one row inserted = first use, zero = replay. Identifiers only; no key
-- material.
CREATE TABLE consumed_ids (
    kind        text NOT NULL
        CHECK (kind IN ('assertion', 'request', 'transition_event')),
    id          uuid NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, id)
);
