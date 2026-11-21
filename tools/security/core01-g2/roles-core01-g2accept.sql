-- CORE-01 G2 — roles for the independent G2 acceptance cluster (port 55460).
-- Contains all roles from roles-pre.sql PLUS the three out-of-band roles that
-- the authorized sandbox (55450) received via build-g2-sandbox.sh but which
-- roles-pre.sql does not define: dl_core_truntime (LOGIN before migration 049
-- sets it NOLOGIN), daleel_core01_authority_definer (BYPASSRLS, needed for
-- migration 059), and dl_provider_issuer (LOGIN, HTTP test pgsql_provider_issuer).
--
-- Identity guard: run only inside the G2 acceptance cluster (55460).
-- This guard is enforced in build-g2accept-cluster.sh before this script is
-- executed; the script refuses if system_identifier == '7702591224362536999'
-- (the authorized sandbox). No check is embedded here to keep the SQL idempotent
-- if re-applied to a completely fresh cluster.
--
-- NEVER run against: production, the authorized sandbox (55450), or any shared
-- acceptance cluster. See build-g2accept-cluster.sh for the full bootstrap flow.

BEGIN;

-- ── Group / service roles (NOLOGIN) ─────────────────────────────────────────
CREATE ROLE daleel_provider_first_admin_writer NOLOGIN;
CREATE ROLE daleel_tenant_auth_lookup           NOLOGIN;
CREATE ROLE daleel_provider_registry_writer     NOLOGIN;
CREATE ROLE daleel_tenant_runtime               NOLOGIN;
CREATE ROLE daleel_hostname_resolver            NOLOGIN;
CREATE ROLE daleel_tenant_auth_client           NOLOGIN;

-- daleel_tenant_auth_lookup is a member of daleel_hostname_resolver so the
-- existing auth-lookup path can also perform host resolution.
GRANT daleel_hostname_resolver TO daleel_tenant_auth_lookup;

-- ── CORE-01 authority definer (NOT in roles-pre.sql) ────────────────────────
-- BYPASSRLS/NOINHERIT NOLOGIN: the definer for tenant-authority functions.
-- Migration 059 requires exactly 1 member of this role (daleel_b10b_owner)
-- during migration (granted transiently in build-g2accept-cluster.sh), and
-- transfers ownership of authority functions to this role.
CREATE ROLE daleel_core01_authority_definer
    NOLOGIN NOINHERIT BYPASSRLS
    NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- ── dl_core_truntime (NOT in roles-pre.sql) ─────────────────────────────────
-- The runtime data-plane identity. LOGIN here so migration 039 passes its
-- pre-flight check (requires LOGIN + MEMBER + USAGE of daleel_tenant_runtime,
-- and SET=FALSE — cannot "become" the group, can only inherit its privileges).
-- Migration 049 will set it NOLOGIN as the fresh-install staging default.
-- The build script proves fail-closed (NOLOGIN after 049), then restores LOGIN.
-- NOTE: cannot use IN ROLE — that syntax sets SET=TRUE (default in PG16).
--       The explicit GRANT with INHERIT TRUE, SET FALSE is required.
CREATE ROLE dl_core_truntime
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT daleel_tenant_runtime TO dl_core_truntime WITH INHERIT TRUE, SET FALSE;

-- ── Standard LOGIN roles (same as roles-pre.sql) ────────────────────────────
CREATE ROLE dl_provider
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

CREATE ROLE dl_provider_ctl
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    IN ROLE daleel_provider_registry_writer, daleel_provider_first_admin_writer;

CREATE ROLE dl_onboarding
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- Correct host-resolution identity: dl_host IN daleel_hostname_resolver.
-- The HTTP test's pgsql_hostname_resolver connection must use 'dl_host',
-- NOT 'dl_tauth'. dl_tauth is only in daleel_tenant_auth_client.
CREATE ROLE dl_host
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    IN ROLE daleel_hostname_resolver;

CREATE ROLE dl_tauth
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    IN ROLE daleel_tenant_auth_client;

CREATE ROLE dl_truntime
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    IN ROLE daleel_tenant_runtime;

-- ── dl_provider_issuer (NOT in roles-pre.sql) ────────────────────────────────
-- LOGIN + NOINHERIT issuer identity for the pgsql_provider_issuer connection.
-- Migration 056 requires: LOGIN, NOT rolinherit, NOT super/bypass/createdb/createrole.
CREATE ROLE dl_provider_issuer
    LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

-- ── Deploy owner ─────────────────────────────────────────────────────────────
-- D1 HARDENED (T4b): NO standing daleel_tenant_auth_lookup membership.
-- build-g2accept-cluster.sh lends this membership transiently for migrations
-- 026/047 and REVOKEs it in a failure-safe block afterward.
CREATE ROLE daleel_b10b_owner
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

CREATE ROLE daleel_b10b_tenant_runtime
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    IN ROLE daleel_tenant_runtime;

CREATE ROLE daleel_b10b_provider_runtime
    LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
    IN ROLE dl_provider;

COMMIT;
