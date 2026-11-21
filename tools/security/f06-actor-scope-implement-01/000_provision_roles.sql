-- SECURITY-F06-LARAVEL-IMPLEMENT-02: role provisioning REQUIRED before running the
-- real product migrations on this sandbox. The migrations themselves (026, 027,
-- 037, 038, hostname-registry migrations) only VERIFY these roles pre-exist as
-- safe NOLOGIN groups; they never create them. This mirrors the real, confirmed
-- operational gap (no provisioning code exists in the repo) and is reproduced
-- here only as a sandbox precondition, not as a product fix.

-- NOLOGIN least-privilege group roles required by migrations 015/019/026/027/037/038.
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_tenant_runtime') THEN
        CREATE ROLE daleel_tenant_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_tenant_auth_lookup') THEN
        CREATE ROLE daleel_tenant_auth_lookup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_tenant_auth_client') THEN
        CREATE ROLE daleel_tenant_auth_client NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_hostname_resolver') THEN
        CREATE ROLE daleel_hostname_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_provider_registry_writer') THEN
        CREATE ROLE daleel_provider_registry_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_provider_first_admin_writer') THEN
        -- Migration 027 requires this role inherit NO other role.
        CREATE ROLE daleel_provider_first_admin_writer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
    END IF;
END
$roles$;

-- migration 026 requires daleel_tenant_auth_lookup to inherit daleel_hostname_resolver (USAGE).
GRANT daleel_hostname_resolver TO daleel_tenant_auth_lookup;

-- migration 026 requires the migration-running principal to be a MEMBER of
-- daleel_tenant_auth_lookup (fact check, not a privilege elevation -- postgres
-- already has superuser privilege; this only satisfies the membership assertion).
GRANT daleel_tenant_auth_lookup TO postgres;

-- Actual LOGIN roles used by the Laravel app connections in this sandbox. Each is
-- a thin SCRAM-authenticated member of the corresponding NOLOGIN group above, so
-- it inherits exactly that group's grants -- never CREATEROLE/CREATEDB/SUPERUSER/
-- BYPASSRLS, and never ownership of any object.
DO $login$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_shared_bootstrap') THEN
        CREATE ROLE daleel_f06i02_shared_bootstrap LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            IN ROLE daleel_tenant_runtime PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_actor_a1') THEN
        CREATE ROLE daleel_f06i02_actor_a1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_actor_a2') THEN
        CREATE ROLE daleel_f06i02_actor_a2 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_actor_b1') THEN
        CREATE ROLE daleel_f06i02_actor_b1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i03_actor_a4') THEN
        CREATE ROLE daleel_f06i03_actor_a4 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_auth_client') THEN
        CREATE ROLE daleel_f06i02_auth_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            IN ROLE daleel_tenant_auth_client PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_hostname_resolver_client') THEN
        CREATE ROLE daleel_f06i02_hostname_resolver_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
            IN ROLE daleel_hostname_resolver PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i02_bootstrap_client') THEN
        -- Dedicated login for TrustedActorBootstrapVerifier; EXECUTE-only on the
        -- narrow lookup function created in 002_actor_sql_fixture.sql, no table grants.
        CREATE ROLE daleel_f06i02_bootstrap_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i03_unused_client') THEN
        -- Used only to pin unrelated provider/onboarding connections to this sandbox.
        CREATE ROLE daleel_f06i03_unused_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i03_provider_auth_client') THEN
        CREATE ROLE daleel_f06i03_provider_auth_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'daleel_f06i03_provider_control_client') THEN
        CREATE ROLE daleel_f06i03_provider_control_client LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD NULL;
    END IF;
    -- A3 (suspended staff) deliberately gets no LOGIN role at all.
END
$login$;

-- Actors inherit the runtime grants but cannot become the shared group role.
-- PostgreSQL 16 defaults SET to TRUE for memberships created by IN ROLE.
GRANT daleel_tenant_runtime TO daleel_f06i02_actor_a1 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT daleel_tenant_runtime TO daleel_f06i02_actor_a2 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT daleel_tenant_runtime TO daleel_f06i02_actor_b1 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;
GRANT daleel_tenant_runtime TO daleel_f06i03_actor_a4 WITH ADMIN FALSE, INHERIT TRUE, SET FALSE;

-- Passwords set outside DO bodies (psql :'var' substitution does not cross $$ bodies).
ALTER ROLE daleel_f06i02_shared_bootstrap PASSWORD :'shared_bootstrap_password';
ALTER ROLE daleel_f06i02_actor_a1 PASSWORD :'actor_a1_password';
ALTER ROLE daleel_f06i02_actor_a2 PASSWORD :'actor_a2_password';
ALTER ROLE daleel_f06i02_actor_b1 PASSWORD :'actor_b1_password';
ALTER ROLE daleel_f06i03_actor_a4 PASSWORD :'actor_a4_password';
ALTER ROLE daleel_f06i02_auth_client PASSWORD :'auth_client_password';
ALTER ROLE daleel_f06i02_hostname_resolver_client PASSWORD :'hostname_resolver_password';
ALTER ROLE daleel_f06i02_bootstrap_client PASSWORD :'bootstrap_client_password';
ALTER ROLE daleel_f06i03_unused_client PASSWORD :'unused_client_password';
ALTER ROLE daleel_f06i03_provider_auth_client PASSWORD :'provider_auth_password';
ALTER ROLE daleel_f06i03_provider_control_client PASSWORD :'provider_control_password';

-- Safety assertion mirroring the migrations' own guard pattern.
DO $guard$
DECLARE r record;
BEGIN
    FOR r IN SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
             FROM pg_roles WHERE rolname LIKE 'daleel_f06i02_%' OR rolname LIKE 'daleel_f06i03_%'
    LOOP
        IF r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls THEN
            RAISE EXCEPTION 'login role % has excess privilege', r.rolname;
        END IF;
    END LOOP;
END
$guard$;
