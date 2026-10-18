-- ADR-0021 two-role setup for the portal. Run ONCE, after the P0-8 store
-- migration has created the store tables in `public`.
--
-- Result: Django (default connection) connects as `portal_app`, which owns the
-- `portal` schema and has no privileges on the store tables at all (review
-- F36: it used to be the postgres superuser, so Django could write the store).
-- The portal's `store` alias connects as `portal_ro`, which has SELECT only on
-- the store tables. The ADR-0014 boundary becomes a Postgres permission, not a
-- convention.

-- Django's own role. Dev-only password set by deploy/run_portal_demo.py.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'portal_app') THEN
        CREATE ROLE portal_app LOGIN;
    END IF;
END
$$;

-- Django's own tables live here, owned by portal_app.
CREATE SCHEMA IF NOT EXISTS portal AUTHORIZATION portal_app;
ALTER SCHEMA portal OWNER TO portal_app;
-- Tables an earlier run created as another role move to portal_app too.
DO $$
DECLARE obj record;
BEGIN
    FOR obj IN SELECT tablename FROM pg_tables WHERE schemaname = 'portal' LOOP
        EXECUTE format('ALTER TABLE portal.%I OWNER TO portal_app', obj.tablename);
    END LOOP;
    FOR obj IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'portal' LOOP
        EXECUTE format('ALTER SEQUENCE portal.%I OWNER TO portal_app', obj.sequencename);
    END LOOP;
END
$$;
-- No store privileges for the app role, now or later.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM portal_app;
REVOKE CREATE ON SCHEMA public FROM portal_app;

-- Read-only role the portal uses for the `store` alias. Created without a
-- password here (trust auth in the README's throwaway container);
-- deploy/run_portal_demo.py sets the dev-only password `portal_ro` afterwards
-- for password-auth Postgres instances. In any real deployment, give it one.
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
