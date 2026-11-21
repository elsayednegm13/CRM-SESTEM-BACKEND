-- ============================================================================
-- F06 ACTOR POC (POC02) — 001: roles, protected identity map, anchored RLS
-- ----------------------------------------------------------------------------
-- Goal: an actor identity anchor that a holder of actor A1's SQL connection
-- cannot forge, so that A1 cannot (a) read/modify A2's restricted resources,
-- (b) escalate itself, or (c) touch tenant B — even with arbitrary SQL and
-- even while setting every GUC the legacy design trusted.
--
-- Anchor = the authenticated SQL login (session_user), resolved through a
-- mapping table that no login role can read or write, via SECURITY DEFINER
-- functions owned by a separate non-login owner role.
--
-- Deliberately NOT used as a source of trust anywhere below:
--   current_setting('app.tenant_id') / ('app.user_id') / ('app.context_mode')
--
-- Run as superuser, on the POC02 sandbox database ONLY (identity is asserted
-- by run_tests.sh before anything executes). SCOPED_EQUIVALENT schema: this
-- is not a replay of the product's migrations 001-038.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 0) Refuse to run twice / refuse to collide with POC01 role names.
-- ---------------------------------------------------------------------------
DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'poc02\_%') THEN
        RAISE EXCEPTION 'poc02_* roles already exist — refusing to reuse/overwrite an existing sandbox';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'poc_runtime%') THEN
        RAISE EXCEPTION 'POC01 roles found in this database — wrong target, refusing to run';
    END IF;
END
$guard$;

-- ---------------------------------------------------------------------------
-- 1) Owner role (NOLOGIN) — owns tables + resolver functions. Separate from
--    every test login role, so no test credential owns the anchor.
-- ---------------------------------------------------------------------------
CREATE ROLE poc02_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

-- ---------------------------------------------------------------------------
-- 2) One LOGIN role per (tenant, actor). No memberships between them, no
--    inheritance, no CREATEROLE/CREATEDB/BYPASSRLS/SUPERUSER.
--      tenant A: a1 (plain), a2 (admin), a3 (suspended), a4 (plain peer)
--      tenant B: b1 (plain)
--    plus poc02_tenant_a_shared, used ONLY by the tenant-only comparison
--    model (003_comparison.sql) to reproduce POC01's weaker anchor.
-- ---------------------------------------------------------------------------
CREATE ROLE poc02_a1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a1';
CREATE ROLE poc02_a2 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a2';
CREATE ROLE poc02_a3 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a3';
CREATE ROLE poc02_a4 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a4';
CREATE ROLE poc02_b1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_b1';
CREATE ROLE poc02_tenant_a_shared LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_shared';

-- No login role may create objects in public (PG15+ already revokes this from
-- PUBLIC, restated here as an explicit invariant of the model).
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO poc02_a1, poc02_a2, poc02_a3, poc02_a4, poc02_b1, poc02_tenant_a_shared;

-- ---------------------------------------------------------------------------
-- 3) The anchor: protected mapping role_name -> (tenant, actor, status, admin)
--    No login role is granted ANY privilege on this table. It is read only
--    through SECURITY DEFINER resolvers owned by poc02_owner.
-- ---------------------------------------------------------------------------
CREATE TABLE actor_identity_map (
    role_name     name PRIMARY KEY,
    tenant_id     uuid NOT NULL,
    actor_id      uuid NOT NULL,
    actor_status  text NOT NULL CHECK (actor_status IN ('ACTIVE','SUSPENDED')),
    is_admin      boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id, actor_id)
);
ALTER TABLE actor_identity_map OWNER TO poc02_owner;
ALTER TABLE actor_identity_map ENABLE ROW LEVEL SECURITY;
-- FORCE RLS is intentionally NOT set here: the table is protected by ACL
-- (zero grants to login roles), and the DEFINER resolvers must be able to
-- read it as poc02_owner. The policy below keeps that explicit.
CREATE POLICY actor_identity_map_owner_only ON actor_identity_map
    FOR SELECT TO poc02_owner USING (true);
REVOKE ALL ON TABLE actor_identity_map FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 4) Resolvers.
--
--    SECURITY DEFINER + session_user is the anchor actually used by the RLS
--    policies below. Rationale, verified empirically by AT11:
--      * inside a SECURITY DEFINER function, current_user becomes the FUNCTION
--        OWNER (poc02_owner), so keying on current_user there would resolve
--        every caller to the owner — the exact trap to avoid;
--      * session_user stays the authenticated login that opened the session and
--        is not changed by SET ROLE, so it cannot be repointed by the caller.
--    Both are proven by poc02_identity_probe_definer() / _invoker() below.
--
--    search_path is pinned on every function and every reference is schema
--    qualified, so a caller-controlled search_path (incl. pg_temp shadowing)
--    cannot redirect the lookup (AT10).
-- ---------------------------------------------------------------------------
CREATE FUNCTION app_actor_tenant() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT m.tenant_id FROM public.actor_identity_map m
    WHERE m.role_name = session_user AND m.actor_status = 'ACTIVE'
$$;

CREATE FUNCTION app_actor_id() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT m.actor_id FROM public.actor_identity_map m
    WHERE m.role_name = session_user AND m.actor_status = 'ACTIVE'
$$;

CREATE FUNCTION app_actor_is_admin() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT coalesce(
        (SELECT m.is_admin FROM public.actor_identity_map m
          WHERE m.role_name = session_user AND m.actor_status = 'ACTIVE'),
        false)
$$;

-- Probes used by AT11 to prove the CURRENT_USER/SESSION_USER semantics rather
-- than assuming them. Return values only; they grant nothing.
CREATE FUNCTION poc02_identity_probe_definer()
    RETURNS TABLE (ctx text, current_u name, session_u name)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT 'definer'::text, current_user, session_user
$$;

CREATE FUNCTION poc02_identity_probe_invoker()
    RETURNS TABLE (ctx text, current_u name, session_u name)
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT 'invoker'::text, current_user, session_user
$$;

-- A deliberately WRONG resolver, kept to demonstrate the trap in AT11:
-- keying on current_user inside a DEFINER function resolves to the owner.
CREATE FUNCTION poc02_wrong_actor_tenant_via_current_user() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT m.tenant_id FROM public.actor_identity_map m
    WHERE m.role_name = current_user AND m.actor_status = 'ACTIVE'
$$;

ALTER FUNCTION app_actor_tenant() OWNER TO poc02_owner;
ALTER FUNCTION app_actor_id() OWNER TO poc02_owner;
ALTER FUNCTION app_actor_is_admin() OWNER TO poc02_owner;
ALTER FUNCTION poc02_identity_probe_definer() OWNER TO poc02_owner;
ALTER FUNCTION poc02_identity_probe_invoker() OWNER TO poc02_owner;
ALTER FUNCTION poc02_wrong_actor_tenant_via_current_user() OWNER TO poc02_owner;

REVOKE ALL ON FUNCTION app_actor_tenant() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_actor_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION app_actor_is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION poc02_wrong_actor_tenant_via_current_user() FROM PUBLIC;
-- Probes stay executable so the tests can observe semantics.

GRANT EXECUTE ON FUNCTION app_actor_tenant(), app_actor_id(), app_actor_is_admin()
    TO poc02_a1, poc02_a2, poc02_a3, poc02_a4, poc02_b1;
GRANT EXECUTE ON FUNCTION poc02_wrong_actor_tenant_via_current_user() TO poc02_a1;

-- ---------------------------------------------------------------------------
-- 5) Business tables, anchored on the resolvers only.
-- ---------------------------------------------------------------------------
CREATE TABLE leads_actor (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    name           text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE leads_actor OWNER TO poc02_owner;
ALTER TABLE leads_actor ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_actor FORCE ROW LEVEL SECURITY;

CREATE POLICY leads_actor_select ON leads_actor FOR SELECT
    USING (
        tenant_id = public.app_actor_tenant()
        AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin())
    );
CREATE POLICY leads_actor_insert ON leads_actor FOR INSERT
    WITH CHECK (
        tenant_id = public.app_actor_tenant()
        AND owner_actor_id = public.app_actor_id()
    );
CREATE POLICY leads_actor_update ON leads_actor FOR UPDATE
    USING (
        tenant_id = public.app_actor_tenant()
        AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin())
    )
    WITH CHECK (tenant_id = public.app_actor_tenant());
CREATE POLICY leads_actor_delete ON leads_actor FOR DELETE
    USING (
        tenant_id = public.app_actor_tenant()
        AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin())
    );

REVOKE ALL ON TABLE leads_actor FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE leads_actor
    TO poc02_a1, poc02_a2, poc02_a3, poc02_a4, poc02_b1;

-- Admin-restricted resource: only an actor whose mapped row says is_admin.
CREATE TABLE admin_grants (
    tenant_id        uuid NOT NULL,
    grantee_actor_id uuid NOT NULL,
    capability       text NOT NULL,
    PRIMARY KEY (tenant_id, grantee_actor_id, capability)
);
ALTER TABLE admin_grants OWNER TO poc02_owner;
ALTER TABLE admin_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY admin_grants_admin_only ON admin_grants FOR ALL
    USING (tenant_id = public.app_actor_tenant() AND public.app_actor_is_admin())
    WITH CHECK (tenant_id = public.app_actor_tenant() AND public.app_actor_is_admin());

REVOKE ALL ON TABLE admin_grants FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE admin_grants
    TO poc02_a1, poc02_a2, poc02_a3, poc02_a4, poc02_b1;

COMMIT;
