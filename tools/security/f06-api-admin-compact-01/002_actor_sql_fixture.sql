-- SECURITY-F06-LARAVEL-IMPLEMENT-02: sandbox-only SQL artifacts that add a
-- session_user-keyed RESTRICTIVE RLS layer on top of the REAL migration-036
-- policies (which remain untouched, GUC-based, permissive). This is additive
-- and reversible (DROP POLICY/TABLE/FUNCTION), not a product migration.
--
-- Why RESTRICTIVE, not another PERMISSIVE policy: PostgreSQL OR-combines
-- multiple PERMISSIVE policies for the same command, so a second permissive
-- policy would NOT close the GUC-spoofing hole (either one passing grants
-- access). A RESTRICTIVE policy AND-combines with the permissive result, so an
-- actor role must satisfy BOTH the legacy GUC check AND the session_user-keyed
-- check. Scoped `TO` the actor roles only, so the FLAG=OFF / shared-bootstrap
-- login path (which never authenticates as one of these roles) is completely
-- unaffected by this file.

BEGIN;

CREATE ROLE daleel_f06i02_identity_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

CREATE TABLE public.f06i02_actor_sql_identity_map (
    tenant_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    sql_role_name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, membership_id),
    FOREIGN KEY (tenant_id, membership_id) REFERENCES public.tenant_staff_memberships(tenant_id, id)
);
ALTER TABLE public.f06i02_actor_sql_identity_map OWNER TO daleel_f06i02_identity_resolver;

INSERT INTO public.f06i02_actor_sql_identity_map (tenant_id, membership_id, sql_role_name) VALUES
    ('11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a001', 'daleel_f06i02_actor_a1'),
    ('11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a002', 'daleel_f06i02_actor_a2'),
    ('11111111-1111-1111-1111-111111111111', 'a1111111-0000-0000-0000-00000000a004', 'daleel_f06i03_actor_a4'),
    ('22222222-2222-2222-2222-222222222222', 'b1111111-0000-0000-0000-00000000b001', 'daleel_f06i02_actor_b1');
    -- A3 (suspended, membership a1111111-...-00000000a003) is deliberately NOT mapped.

-- session_user -> tenant_id, via SECURITY DEFINER so actor roles need no direct
-- grant on the mapping table (and cannot read/alter their own mapping row).
CREATE OR REPLACE FUNCTION public.f06i02_actor_tenant_id() RETURNS uuid AS $fn$
    SELECT m.tenant_id FROM public.f06i02_actor_sql_identity_map m WHERE m.sql_role_name = session_user;
$fn$ LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public;
ALTER FUNCTION public.f06i02_actor_tenant_id OWNER TO daleel_f06i02_identity_resolver;
REVOKE ALL ON FUNCTION public.f06i02_actor_tenant_id FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06i02_actor_tenant_id TO daleel_f06i02_actor_a1, daleel_f06i02_actor_a2, daleel_f06i02_actor_b1, daleel_f06i03_actor_a4;

CREATE POLICY f06i02_leads_actor_tenant_boundary ON public.leads
    AS RESTRICTIVE
    TO daleel_f06i02_actor_a1, daleel_f06i02_actor_a2, daleel_f06i02_actor_b1, daleel_f06i03_actor_a4
    USING (tenant_id = public.f06i02_actor_tenant_id())
    WITH CHECK (tenant_id = public.f06i02_actor_tenant_id());

-- Bootstrap lookup: real-schema equivalent of IMPLEMENT-01's function, used only
-- by TrustedActorBootstrapVerifier via the dedicated pgsql_f06_bootstrap connection.
CREATE OR REPLACE FUNCTION public.f06i02_bootstrap_lookup(
    p_tenant_id uuid, p_staff_user_id uuid, p_membership_id uuid,
    p_auth_version integer, p_authorization_version integer
) RETURNS TABLE(sql_role_name text) AS $fn$
DECLARE
    previous_mode text := pg_catalog.current_setting('app.context_mode', true);
    previous_tenant text := pg_catalog.current_setting('app.tenant_id', true);
    previous_user text := pg_catalog.current_setting('app.user_id', true);
BEGIN
    IF session_user <> 'daleel_f06i02_bootstrap_client' THEN
        RAISE EXCEPTION 'bootstrap lookup is restricted to the bootstrap client role';
    END IF;

    -- tenants/tenant_staff_users/tenant_staff_memberships carry FORCE ROW LEVEL
    -- SECURITY with a generic "TENANT" scope policy (app_rls_context_mode()='TENANT'
    -- AND tenant_id=app_rls_current_tenant_id()); this SECURITY DEFINER function is
    -- not exempt from that (FORCE applies even to the function owner), so it must
    -- set the same GUCs the real request-context guard sets, scoped to p_tenant_id
    -- only, and restore the prior values before returning.
    PERFORM pg_catalog.set_config('app.context_mode', 'TENANT', true);
    PERFORM pg_catalog.set_config('app.tenant_id', p_tenant_id::text, true);
    PERFORM pg_catalog.set_config('app.user_id', p_staff_user_id::text, true);

    RETURN QUERY
    SELECT m.sql_role_name
    FROM public.tenants t
    JOIN public.tenant_staff_users u ON u.tenant_id = t.id
    JOIN public.tenant_staff_memberships ms ON ms.tenant_id = t.id AND ms.staff_user_id = u.id
    JOIN public.f06i02_actor_sql_identity_map m ON m.tenant_id = ms.tenant_id AND m.membership_id = ms.id
    WHERE t.id = p_tenant_id AND t.status = 'ACTIVE'
      AND u.id = p_staff_user_id AND u.status = 'ACTIVE' AND u.auth_version = p_auth_version
      AND ms.id = p_membership_id AND ms.status = 'ACTIVE' AND ms.authorization_version = p_authorization_version;

    PERFORM pg_catalog.set_config('app.context_mode', coalesce(previous_mode, ''), true);
    PERFORM pg_catalog.set_config('app.tenant_id', coalesce(previous_tenant, ''), true);
    PERFORM pg_catalog.set_config('app.user_id', coalesce(previous_user, ''), true);
END;
$fn$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
ALTER FUNCTION public.f06i02_bootstrap_lookup OWNER TO daleel_f06i02_identity_resolver;
REVOKE ALL ON FUNCTION public.f06i02_bootstrap_lookup FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06i02_bootstrap_lookup TO daleel_f06i02_bootstrap_client;
GRANT SELECT ON public.tenants, public.tenant_staff_users, public.tenant_staff_memberships, public.f06i02_actor_sql_identity_map
    TO daleel_f06i02_identity_resolver;
-- Bootstrap client has NO direct table access -- EXECUTE on the function only.
REVOKE ALL ON public.tenants, public.tenant_staff_users, public.tenant_staff_memberships,
    public.f06i02_actor_sql_identity_map, public.leads FROM daleel_f06i02_bootstrap_client;
GRANT USAGE ON SCHEMA public TO daleel_f06i02_bootstrap_client;

COMMIT;
