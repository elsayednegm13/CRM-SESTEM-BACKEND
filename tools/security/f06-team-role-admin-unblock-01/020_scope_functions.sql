-- Sandbox-only actor authority derived from session_user. No product migration.
BEGIN;
CREATE ROLE daleel_f06scope_resolver NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO daleel_f06scope_resolver;
GRANT SELECT (id, status) ON public.tenants TO daleel_f06scope_resolver;
GRANT SELECT (id, tenant_id, status, auth_version) ON public.tenant_staff_users TO daleel_f06scope_resolver;
GRANT SELECT (id, tenant_id, staff_user_id, status, authorization_version) ON public.tenant_staff_memberships TO daleel_f06scope_resolver;
GRANT SELECT (tenant_id, membership_id, role_id, revoked_at) ON public.tenant_staff_membership_roles TO daleel_f06scope_resolver;
GRANT SELECT (id, tenant_id, status, archived_at) ON public.roles TO daleel_f06scope_resolver;
GRANT SELECT (tenant_id, role_id, permission_key, scope) ON public.role_permissions TO daleel_f06scope_resolver;
GRANT SELECT (tenant_id, membership_id, permission_key, scope, revoked_at) ON public.tenant_staff_permission_grants TO daleel_f06scope_resolver;
GRANT SELECT (key, status, scopeable, allowed_scopes, delegable) ON public.permissions TO daleel_f06scope_resolver;

CREATE TABLE public.f06scope_actor_identity_map (
    sql_role_name name PRIMARY KEY,
    tenant_id uuid NOT NULL,
    membership_id uuid NOT NULL,
    staff_user_id uuid NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    UNIQUE (tenant_id, membership_id),
    FOREIGN KEY (tenant_id, membership_id) REFERENCES public.tenant_staff_memberships(tenant_id, id)
);
ALTER TABLE public.f06scope_actor_identity_map OWNER TO daleel_f06scope_resolver;
REVOKE ALL ON public.f06scope_actor_identity_map FROM PUBLIC;
INSERT INTO public.f06scope_actor_identity_map(sql_role_name,tenant_id,membership_id,staff_user_id)
SELECT old.sql_role_name,old.tenant_id,old.membership_id,m.staff_user_id
FROM public.f06i02_actor_sql_identity_map old
JOIN public.tenant_staff_memberships m ON m.tenant_id=old.tenant_id AND m.id=old.membership_id;

CREATE FUNCTION public.f06scope_actor_claim()
RETURNS TABLE(actor_tenant uuid,actor_membership uuid,actor_user uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE x record;
    old_mode text := pg_catalog.current_setting('app.context_mode',true);
    old_tenant text := pg_catalog.current_setting('app.tenant_id',true);
    old_user text := pg_catalog.current_setting('app.user_id',true);
BEGIN
    SELECT m.tenant_id,m.membership_id,m.staff_user_id INTO x
    FROM public.f06scope_actor_identity_map m
    WHERE m.sql_role_name=session_user AND m.enabled=true;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('app.context_mode','TENANT',true);
        PERFORM pg_catalog.set_config('app.tenant_id',x.tenant_id::text,true);
        PERFORM pg_catalog.set_config('app.user_id',x.staff_user_id::text,true);
        IF EXISTS (SELECT 1 FROM public.tenants t
                   JOIN public.tenant_staff_users u ON u.tenant_id=t.id AND u.id=x.staff_user_id
                   JOIN public.tenant_staff_memberships ms ON ms.tenant_id=t.id AND ms.id=x.membership_id AND ms.staff_user_id=u.id
                   WHERE t.id=x.tenant_id AND t.status='ACTIVE' AND u.status='ACTIVE' AND ms.status='ACTIVE') THEN
            RETURN QUERY SELECT x.tenant_id,x.membership_id,x.staff_user_id;
        END IF;
    END IF;
    PERFORM pg_catalog.set_config('app.context_mode',coalesce(old_mode,''),true);
    PERFORM pg_catalog.set_config('app.tenant_id',coalesce(old_tenant,''),true);
    PERFORM pg_catalog.set_config('app.user_id',coalesce(old_user,''),true);
END;
$fn$;
ALTER FUNCTION public.f06scope_actor_claim() OWNER TO daleel_f06scope_resolver;
REVOKE ALL ON FUNCTION public.f06scope_actor_claim() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06scope_actor_claim() TO daleel_f06scope_actor_runtime;

CREATE FUNCTION public.f06scope_effective_scopes(p_key text)
RETURNS text[] LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE t uuid; m uuid; u uuid; g record; p record; out_scopes text[] := ARRAY[]::text[];
    old_mode text := pg_catalog.current_setting('app.context_mode',true);
    old_tenant text := pg_catalog.current_setting('app.tenant_id',true);
    old_user text := pg_catalog.current_setting('app.user_id',true);
    invalid boolean := false;
BEGIN
    SELECT actor_tenant,actor_membership,actor_user INTO t,m,u FROM public.f06scope_actor_claim();
    IF t IS NULL THEN RETURN NULL; END IF;
    PERFORM pg_catalog.set_config('app.context_mode','TENANT',true);
    PERFORM pg_catalog.set_config('app.tenant_id',t::text,true);
    PERFORM pg_catalog.set_config('app.user_id',u::text,true);
    FOR g IN
        SELECT rp.permission_key,rp.scope,false AS is_direct
        FROM public.tenant_staff_membership_roles mr
        JOIN public.roles r ON r.tenant_id=mr.tenant_id AND r.id=mr.role_id
        JOIN public.role_permissions rp ON rp.tenant_id=r.tenant_id AND rp.role_id=r.id
        WHERE mr.tenant_id=t AND mr.membership_id=m AND mr.revoked_at IS NULL
          AND r.status='ACTIVE' AND r.archived_at IS NULL
        UNION ALL
        SELECT dg.permission_key,dg.scope,true
        FROM public.tenant_staff_permission_grants dg
        WHERE dg.tenant_id=t AND dg.membership_id=m AND dg.revoked_at IS NULL
    LOOP
        SELECT status,scopeable,allowed_scopes,delegable INTO p
        FROM public.permissions WHERE key=g.permission_key;
        IF NOT FOUND OR p.status IS DISTINCT FROM 'ACTIVE'
           OR p.scopeable IS NULL OR p.delegable IS NULL
           OR (g.is_direct AND p.delegable IS DISTINCT FROM true)
           OR pg_catalog.jsonb_typeof(p.allowed_scopes) IS DISTINCT FROM 'array'
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements_text(p.allowed_scopes) a(v)
                      WHERE a.v NOT IN ('ALL_TENANT','TEAM','ASSIGNED','SELF','NONE'))
           OR (p.scopeable AND (g.scope IS NULL OR NOT p.allowed_scopes @> pg_catalog.jsonb_build_array(g.scope)))
           OR (NOT p.scopeable AND (g.scope IS NOT NULL OR p.allowed_scopes <> '[]'::jsonb)) THEN
            invalid := true; EXIT;
        END IF;
        IF g.permission_key=p_key AND g.scope IS DISTINCT FROM 'NONE'
           AND NOT (g.scope = ANY(out_scopes)) THEN
            out_scopes := pg_catalog.array_append(out_scopes,g.scope);
        END IF;
    END LOOP;
    PERFORM pg_catalog.set_config('app.context_mode',coalesce(old_mode,''),true);
    PERFORM pg_catalog.set_config('app.tenant_id',coalesce(old_tenant,''),true);
    PERFORM pg_catalog.set_config('app.user_id',coalesce(old_user,''),true);
    IF invalid THEN RETURN NULL; END IF;
    RETURN out_scopes;
END;
$fn$;
ALTER FUNCTION public.f06scope_effective_scopes(text) OWNER TO daleel_f06scope_resolver;
REVOKE ALL ON FUNCTION public.f06scope_effective_scopes(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06scope_effective_scopes(text) TO daleel_f06scope_actor_runtime;

CREATE FUNCTION public.f06scope_row_allowed(p_key text,p_tenant uuid,p_assigned uuid,p_created uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE t uuid; m uuid; u uuid; scopes text[];
BEGIN
    SELECT actor_tenant,actor_membership,actor_user INTO t,m,u FROM public.f06scope_actor_claim();
    IF t IS NULL OR t IS DISTINCT FROM p_tenant OR p_key NOT IN ('leads.view','leads.manage') THEN RETURN false; END IF;
    scopes := public.f06scope_effective_scopes(p_key);
    RETURN coalesce('ALL_TENANT'=ANY(scopes)
        OR ('ASSIGNED'=ANY(scopes) AND p_assigned=m)
        OR ('SELF'=ANY(scopes) AND p_created=m),false);
END;
$fn$;
ALTER FUNCTION public.f06scope_row_allowed(text,uuid,uuid,uuid) OWNER TO daleel_f06scope_resolver;
REVOKE ALL ON FUNCTION public.f06scope_row_allowed(text,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06scope_row_allowed(text,uuid,uuid,uuid) TO daleel_f06scope_actor_runtime;

CREATE FUNCTION public.f06scope_insert_allowed(p_tenant uuid,p_assigned uuid,p_created uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE t uuid; m uuid; u uuid; scopes text[]; target_ok boolean := false;
    old_mode text := pg_catalog.current_setting('app.context_mode',true);
    old_tenant text := pg_catalog.current_setting('app.tenant_id',true);
    old_user text := pg_catalog.current_setting('app.user_id',true);
BEGIN
    SELECT actor_tenant,actor_membership,actor_user INTO t,m,u FROM public.f06scope_actor_claim();
    IF t IS NULL OR t IS DISTINCT FROM p_tenant OR m IS DISTINCT FROM p_created THEN RETURN false; END IF;
    scopes := public.f06scope_effective_scopes('leads.manage');
    IF scopes IS NULL THEN RETURN false; END IF;
    IF 'ALL_TENANT'=ANY(scopes) THEN
        IF p_assigned IS NULL THEN RETURN true; END IF;
        PERFORM pg_catalog.set_config('app.context_mode','TENANT',true);
        PERFORM pg_catalog.set_config('app.tenant_id',t::text,true);
        PERFORM pg_catalog.set_config('app.user_id',u::text,true);
        SELECT EXISTS (SELECT 1 FROM public.tenant_staff_memberships ms
                       WHERE ms.tenant_id=t AND ms.id=p_assigned AND ms.status='ACTIVE') INTO target_ok;
        PERFORM pg_catalog.set_config('app.context_mode',coalesce(old_mode,''),true);
        PERFORM pg_catalog.set_config('app.tenant_id',coalesce(old_tenant,''),true);
        PERFORM pg_catalog.set_config('app.user_id',coalesce(old_user,''),true);
        RETURN target_ok;
    END IF;
    RETURN p_assigned=m AND ('ASSIGNED'=ANY(scopes) OR 'SELF'=ANY(scopes));
END;
$fn$;
ALTER FUNCTION public.f06scope_insert_allowed(uuid,uuid,uuid) OWNER TO daleel_f06scope_resolver;
REVOKE ALL ON FUNCTION public.f06scope_insert_allowed(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06scope_insert_allowed(uuid,uuid,uuid) TO daleel_f06scope_actor_runtime;
COMMIT;
