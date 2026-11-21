-- ============================================================================
-- F06 ACTOR POC — HARDENED (POC03) — 001: roles, anchor, RLS, ownership locks
-- ----------------------------------------------------------------------------
-- Derived from tools/security/f06-actor-poc/001_schema_roles.sql (POC02),
-- which is left untouched. This copy fixes the defects raised by the
-- independent review:
--   S1  UPDATE WITH CHECK did not pin the NEW row's owner  -> column ACL on
--       tenant_id + BEFORE UPDATE trigger comparing OLD/NEW, raising 42501.
--   S2  client-chosen primary key allowed an existence oracle via unique
--       violation -> id is DB-generated and INSERT on the id column is not
--       granted, so a client cannot probe a key it cannot supply.
-- The tenant/actor anchor itself is unchanged in principle: the authenticated
-- SQL login (session_user) resolved through a mapping table no login role can
-- read or write. No policy consults app.tenant_id / app.user_id /
-- app.context_mode.
--
-- Run as superuser on the POC03 sandbox ONLY. SCOPED_EQUIVALENT schema.
-- ============================================================================

BEGIN;

DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'h01\_%') THEN
        RAISE EXCEPTION 'h01_* roles already exist — refusing to reuse a sandbox';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'poc02\_%' OR rolname LIKE 'poc_runtime%') THEN
        RAISE EXCEPTION 'POC01/POC02 roles present — wrong target, refusing to run';
    END IF;
END
$guard$;

-- ---------------------------------------------------------------------------
-- Owner (NOLOGIN) — owns tables, functions and the anchor.
-- ---------------------------------------------------------------------------
CREATE ROLE h01_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

-- One LOGIN per (tenant, actor). No memberships, no inheritance.
CREATE ROLE h01_a1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a1';
CREATE ROLE h01_a2 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a2';
CREATE ROLE h01_a3 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a3';
CREATE ROLE h01_a4 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a4';
CREATE ROLE h01_b1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_b1';
-- Used only by 003_comparison.sql to reproduce the two weaker anchors.
CREATE ROLE h01_shared_a LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_shared';

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1, h01_shared_a;

-- ---------------------------------------------------------------------------
-- The anchor: no login role holds any privilege on this table.
-- ---------------------------------------------------------------------------
CREATE TABLE actor_identity_map (
    role_name    name PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    actor_id     uuid NOT NULL,
    actor_status text NOT NULL CHECK (actor_status IN ('ACTIVE','SUSPENDED')),
    is_admin     boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id, actor_id)
);
ALTER TABLE actor_identity_map OWNER TO h01_owner;
ALTER TABLE actor_identity_map ENABLE ROW LEVEL SECURITY;
CREATE POLICY actor_identity_map_owner_only ON actor_identity_map
    FOR SELECT TO h01_owner USING (true);
REVOKE ALL ON TABLE actor_identity_map FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Resolvers: SECURITY DEFINER, owned by h01_owner, pinned search_path,
-- keyed on session_user (verified semantics, not assumed — see probes).
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
    SELECT coalesce((SELECT m.is_admin FROM public.actor_identity_map m
        WHERE m.role_name = session_user AND m.actor_status = 'ACTIVE'), false)
$$;

CREATE FUNCTION h01_probe_definer() RETURNS TABLE (current_u name, session_u name)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT current_user, session_user $$;
CREATE FUNCTION h01_probe_invoker() RETURNS TABLE (current_u name, session_u name)
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT current_user, session_user $$;
-- Kept to prove the trap: current_user inside DEFINER is the function owner.
CREATE FUNCTION h01_wrong_tenant_via_current_user() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT m.tenant_id FROM public.actor_identity_map m
    WHERE m.role_name = current_user AND m.actor_status = 'ACTIVE' $$;

ALTER FUNCTION app_actor_tenant()  OWNER TO h01_owner;
ALTER FUNCTION app_actor_id()      OWNER TO h01_owner;
ALTER FUNCTION app_actor_is_admin() OWNER TO h01_owner;
ALTER FUNCTION h01_probe_definer() OWNER TO h01_owner;
ALTER FUNCTION h01_probe_invoker() OWNER TO h01_owner;
ALTER FUNCTION h01_wrong_tenant_via_current_user() OWNER TO h01_owner;

REVOKE ALL ON FUNCTION app_actor_tenant()  FROM PUBLIC;
REVOKE ALL ON FUNCTION app_actor_id()      FROM PUBLIC;
REVOKE ALL ON FUNCTION app_actor_is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION h01_probe_definer() FROM PUBLIC;
REVOKE ALL ON FUNCTION h01_probe_invoker() FROM PUBLIC;
REVOKE ALL ON FUNCTION h01_wrong_tenant_via_current_user() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_actor_tenant(), app_actor_id(), app_actor_is_admin(),
                          h01_probe_definer(), h01_probe_invoker(),
                          h01_wrong_tenant_via_current_user()
    TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1;

-- ---------------------------------------------------------------------------
-- Business table.
--   * id is DB-generated; INSERT on the id column is NOT granted (S2).
--   * UNIQUE (tenant_id, code) is kept deliberately so the remaining
--     in-tenant existence channel can be measured honestly rather than
--     hidden (see H03/H04 in run_tests.sh).
--   * tenant_id is not UPDATE-grantable (column ACL);
--     owner_actor_id IS UPDATE-grantable so the ownership trigger is really
--     exercised instead of being unreachable dead code.
-- ---------------------------------------------------------------------------
CREATE TABLE leads_actor (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL,
    owner_actor_id uuid NOT NULL,
    code           text NOT NULL,
    name           text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, code)
);
ALTER TABLE leads_actor OWNER TO h01_owner;
ALTER TABLE leads_actor ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_actor FORCE ROW LEVEL SECURITY;

CREATE POLICY leads_actor_select ON leads_actor FOR SELECT
    USING (tenant_id = public.app_actor_tenant()
           AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()));

-- INSERT: only inside the actor's tenant, only owned by the actor itself
-- (admins included — admin-created rows owned by others are a business
-- contract that this POC deliberately does not grant).
CREATE POLICY leads_actor_insert ON leads_actor FOR INSERT
    WITH CHECK (tenant_id = public.app_actor_tenant()
                AND owner_actor_id = public.app_actor_id());

-- UPDATE: USING protects the OLD row, WITH CHECK pins the NEW row to the
-- actor's own tenant and to an owner the actor is allowed to end up with.
CREATE POLICY leads_actor_update ON leads_actor FOR UPDATE
    USING (tenant_id = public.app_actor_tenant()
           AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()))
    WITH CHECK (tenant_id = public.app_actor_tenant()
                AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()));

CREATE POLICY leads_actor_delete ON leads_actor FOR DELETE
    USING (tenant_id = public.app_actor_tenant()
           AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()));

-- Ownership/tenant immutability: WITH CHECK alone cannot compare OLD vs NEW,
-- so an admin (who satisfies both sides) could still reassign a row. This
-- trigger closes that and raises insufficient_privilege (42501) so the denial
-- classifies as a security control, not as a constraint error.
CREATE FUNCTION h01_leads_actor_lock_ownership() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'tenant_id is immutable on leads_actor'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.owner_actor_id IS DISTINCT FROM OLD.owner_actor_id THEN
        RAISE EXCEPTION 'owner_actor_id is immutable on leads_actor (ownership transfer is not permitted)'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'id is immutable on leads_actor'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;
ALTER FUNCTION h01_leads_actor_lock_ownership() OWNER TO h01_owner;
REVOKE ALL ON FUNCTION h01_leads_actor_lock_ownership() FROM PUBLIC;
CREATE TRIGGER leads_actor_lock_ownership
    BEFORE UPDATE ON leads_actor
    FOR EACH ROW EXECUTE FUNCTION h01_leads_actor_lock_ownership();

REVOKE ALL ON TABLE leads_actor FROM PUBLIC;
GRANT SELECT ON TABLE leads_actor TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1;
-- id and created_at are NOT insertable by clients (S2 mitigation).
GRANT INSERT (tenant_id, owner_actor_id, code, name) ON TABLE leads_actor
    TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1;
-- tenant_id is NOT updatable at all; owner_actor_id is, so the trigger is live.
GRANT UPDATE (code, name, owner_actor_id) ON TABLE leads_actor
    TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1;
GRANT DELETE ON TABLE leads_actor TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1;

-- Admin-restricted resource.
CREATE TABLE admin_grants (
    tenant_id        uuid NOT NULL,
    grantee_actor_id uuid NOT NULL,
    capability       text NOT NULL,
    PRIMARY KEY (tenant_id, grantee_actor_id, capability)
);
ALTER TABLE admin_grants OWNER TO h01_owner;
ALTER TABLE admin_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_grants_admin_only ON admin_grants FOR ALL
    USING (tenant_id = public.app_actor_tenant() AND public.app_actor_is_admin())
    WITH CHECK (tenant_id = public.app_actor_tenant() AND public.app_actor_is_admin());
REVOKE ALL ON TABLE admin_grants FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE admin_grants
    TO h01_a1, h01_a2, h01_a3, h01_a4, h01_b1;

-- NOTE: h01_fingerprint() is defined at the end of 003_comparison.sql,
-- because it also reads the two comparison tables created there.

COMMIT;
