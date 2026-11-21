-- ============================================================================
-- F06 ACTOR POC — FINAL HARDEN (POC04) — 001: roles, anchor, RLS, locks
-- ----------------------------------------------------------------------------
-- Copied from ../f06-actor-poc-harden/001_schema_roles.sql (POC03, untouched)
-- and changed only where the independent review of POC03 required it:
--   F4  effective-privilege checks need a function that deliberately keeps the
--       PostgreSQL DEFAULT ACL (proacl IS NULL => EXECUTE to PUBLIC) so the
--       harness can prove its detector fires. It is created inside a
--       transaction by the test, not here, so the shipped schema stays clean.
--   F6  a dedicated actor (fh_a5) exists for the revocation test, so the
--       reference actors are never suspended.
--   F3  the fingerprint moved to 003 and was widened (see that file).
-- The anchor is unchanged in principle: the authenticated SQL login
-- (session_user) resolved through a mapping table no login role can read or
-- write. No policy or resolver reads app.tenant_id / app.user_id /
-- app.context_mode.
--
-- Run as superuser on the POC04 sandbox ONLY. SCOPED_EQUIVALENT schema.
-- ============================================================================

BEGIN;

DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname LIKE 'fh\_%') THEN
        RAISE EXCEPTION 'fh_* roles already exist — refusing to reuse a sandbox';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles
               WHERE rolname LIKE 'h01\_%' OR rolname LIKE 'poc02\_%' OR rolname LIKE 'poc_runtime%') THEN
        RAISE EXCEPTION 'POC01/POC02/POC03 roles present — wrong target, refusing to run';
    END IF;
END
$guard$;

CREATE ROLE fh_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

-- One LOGIN per (tenant, actor). No memberships, no inheritance.
CREATE ROLE fh_a1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a1';
CREATE ROLE fh_a2 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a2';
CREATE ROLE fh_a3 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a3';
CREATE ROLE fh_a4 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a4';
CREATE ROLE fh_a5 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_a5';
CREATE ROLE fh_b1 LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_b1';
CREATE ROLE fh_shared_a LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD :'pw_shared';

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1, fh_shared_a;

-- ---------------------------------------------------------------------------
-- Anchor table — zero privileges for every login role.
-- ---------------------------------------------------------------------------
CREATE TABLE actor_identity_map (
    role_name    name PRIMARY KEY,
    tenant_id    uuid NOT NULL,
    actor_id     uuid NOT NULL,
    actor_status text NOT NULL CHECK (actor_status IN ('ACTIVE','SUSPENDED')),
    is_admin     boolean NOT NULL DEFAULT false,
    UNIQUE (tenant_id, actor_id)
);
ALTER TABLE actor_identity_map OWNER TO fh_owner;
ALTER TABLE actor_identity_map ENABLE ROW LEVEL SECURITY;
CREATE POLICY actor_identity_map_owner_only ON actor_identity_map
    FOR SELECT TO fh_owner USING (true);
REVOKE ALL ON TABLE actor_identity_map FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Resolvers: SECURITY DEFINER, owner fh_owner, pinned search_path,
-- keyed on session_user. EXECUTE is revoked from PUBLIC explicitly, which is
-- what makes the F4 effective-privilege check meaningful.
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

CREATE FUNCTION fh_probe_definer() RETURNS TABLE (current_u name, session_u name)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT current_user, session_user $$;
CREATE FUNCTION fh_probe_invoker() RETURNS TABLE (current_u name, session_u name)
    LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, public AS $$
    SELECT current_user, session_user $$;
CREATE FUNCTION fh_wrong_tenant_via_current_user() RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    SELECT m.tenant_id FROM public.actor_identity_map m
    WHERE m.role_name = current_user AND m.actor_status = 'ACTIVE' $$;

ALTER FUNCTION app_actor_tenant()   OWNER TO fh_owner;
ALTER FUNCTION app_actor_id()       OWNER TO fh_owner;
ALTER FUNCTION app_actor_is_admin() OWNER TO fh_owner;
ALTER FUNCTION fh_probe_definer()   OWNER TO fh_owner;
ALTER FUNCTION fh_probe_invoker()   OWNER TO fh_owner;
ALTER FUNCTION fh_wrong_tenant_via_current_user() OWNER TO fh_owner;

REVOKE ALL ON FUNCTION app_actor_tenant()   FROM PUBLIC;
REVOKE ALL ON FUNCTION app_actor_id()       FROM PUBLIC;
REVOKE ALL ON FUNCTION app_actor_is_admin() FROM PUBLIC;
REVOKE ALL ON FUNCTION fh_probe_definer()   FROM PUBLIC;
REVOKE ALL ON FUNCTION fh_probe_invoker()   FROM PUBLIC;
REVOKE ALL ON FUNCTION fh_wrong_tenant_via_current_user() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_actor_tenant(), app_actor_id(), app_actor_is_admin(),
                          fh_probe_definer(), fh_probe_invoker(),
                          fh_wrong_tenant_via_current_user()
    TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1;

-- ---------------------------------------------------------------------------
-- Business table. id is DB-generated and not insertable (S2 key channel).
-- UNIQUE (tenant_id, code) is kept so the residual in-tenant existence
-- channel stays measurable (reported as a finding, never as a control pass).
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
ALTER TABLE leads_actor OWNER TO fh_owner;
ALTER TABLE leads_actor ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads_actor FORCE ROW LEVEL SECURITY;

CREATE POLICY leads_actor_select ON leads_actor FOR SELECT
    USING (tenant_id = public.app_actor_tenant()
           AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()));
CREATE POLICY leads_actor_insert ON leads_actor FOR INSERT
    WITH CHECK (tenant_id = public.app_actor_tenant()
                AND owner_actor_id = public.app_actor_id());
CREATE POLICY leads_actor_update ON leads_actor FOR UPDATE
    USING (tenant_id = public.app_actor_tenant()
           AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()))
    WITH CHECK (tenant_id = public.app_actor_tenant()
                AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()));
CREATE POLICY leads_actor_delete ON leads_actor FOR DELETE
    USING (tenant_id = public.app_actor_tenant()
           AND (owner_actor_id = public.app_actor_id() OR public.app_actor_is_admin()));

-- POC-only ownership lock. NOTE (F7): the real product permits authorised
-- re-assignment of leads; this immutability is a POC simplification and must
-- NOT be carried into the product contract.
CREATE FUNCTION fh_leads_actor_lock_ownership() RETURNS trigger
    LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION 'tenant_id is immutable on leads_actor' USING ERRCODE = '42501';
    END IF;
    IF NEW.owner_actor_id IS DISTINCT FROM OLD.owner_actor_id THEN
        RAISE EXCEPTION 'owner_actor_id is immutable on leads_actor (ownership transfer is not permitted)'
            USING ERRCODE = '42501';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'id is immutable on leads_actor' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END
$$;
ALTER FUNCTION fh_leads_actor_lock_ownership() OWNER TO fh_owner;
REVOKE ALL ON FUNCTION fh_leads_actor_lock_ownership() FROM PUBLIC;
CREATE TRIGGER leads_actor_lock_ownership
    BEFORE UPDATE ON leads_actor
    FOR EACH ROW EXECUTE FUNCTION fh_leads_actor_lock_ownership();

REVOKE ALL ON TABLE leads_actor FROM PUBLIC;
GRANT SELECT ON TABLE leads_actor TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1;
GRANT INSERT (tenant_id, owner_actor_id, code, name) ON TABLE leads_actor
    TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1;
GRANT UPDATE (code, name, owner_actor_id) ON TABLE leads_actor
    TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1;
GRANT DELETE ON TABLE leads_actor TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1;

CREATE TABLE admin_grants (
    tenant_id        uuid NOT NULL,
    grantee_actor_id uuid NOT NULL,
    capability       text NOT NULL,
    PRIMARY KEY (tenant_id, grantee_actor_id, capability)
);
ALTER TABLE admin_grants OWNER TO fh_owner;
ALTER TABLE admin_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY admin_grants_admin_only ON admin_grants FOR ALL
    USING (tenant_id = public.app_actor_tenant() AND public.app_actor_is_admin())
    WITH CHECK (tenant_id = public.app_actor_tenant() AND public.app_actor_is_admin());
REVOKE ALL ON TABLE admin_grants FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE admin_grants
    TO fh_a1, fh_a2, fh_a3, fh_a4, fh_a5, fh_b1;

COMMIT;
