-- ADR-0021 two-role setup for the portal. Run ONCE, after the P0-8 store
-- migration has created the store tables in `public`.
--
-- Result: Django (default connection) owns the `portal` schema and writes only
-- there; the portal's `store` alias connects as `portal_ro`, which has SELECT
-- only on the store tables and cannot write them. The ADR-0014 boundary becomes
-- a Postgres permission, not a convention.

-- Django's own tables live here.
CREATE SCHEMA IF NOT EXISTS portal;

-- Read-only role the portal uses for the `store` alias. In dev (trust auth) it
-- connects without a password; in any real deployment, give it one.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'portal_ro') THEN
        CREATE ROLE portal_ro LOGIN;
    END IF;
END
$$;

-- SELECT-only on the store tables, now and for any added later. No write grants
-- are issued, so portal_ro can never INSERT/UPDATE/DELETE the store.
GRANT USAGE ON SCHEMA public TO portal_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO portal_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO portal_ro;
