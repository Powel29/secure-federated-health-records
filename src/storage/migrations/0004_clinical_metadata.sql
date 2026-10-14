ALTER TABLE records ADD COLUMN clinical jsonb NOT NULL DEFAULT '{}'::jsonb;
