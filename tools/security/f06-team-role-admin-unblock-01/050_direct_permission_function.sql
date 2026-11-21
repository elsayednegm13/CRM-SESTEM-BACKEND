-- Sandbox-only bounded direct leads.view:SELF grant/revoke. No product migration.
BEGIN;
CREATE ROLE daleel_f06team01_admin_executor NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO daleel_f06team01_admin_executor;
GRANT SELECT (id,tenant_id,staff_user_id,status,authorization_version)
    ON public.tenant_staff_memberships TO daleel_f06team01_admin_executor;
GRANT UPDATE (authorization_version,updated_at)
    ON public.tenant_staff_memberships TO daleel_f06team01_admin_executor;
GRANT SELECT (tenant_id,membership_id,role_id,revoked_at)
    ON public.tenant_staff_membership_roles TO daleel_f06team01_admin_executor;
GRANT SELECT (id,tenant_id,status,archived_at)
    ON public.roles TO daleel_f06team01_admin_executor;
GRANT SELECT (tenant_id,role_id,permission_key,scope)
    ON public.role_permissions TO daleel_f06team01_admin_executor;
GRANT SELECT (id,tenant_id,membership_id,permission_key,scope,revoked_at)
    ON public.tenant_staff_permission_grants TO daleel_f06team01_admin_executor;
GRANT INSERT (id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at)
    ON public.tenant_staff_permission_grants TO daleel_f06team01_admin_executor;
GRANT UPDATE (revoked_at,revoked_by_membership_id,updated_at)
    ON public.tenant_staff_permission_grants TO daleel_f06team01_admin_executor;
GRANT SELECT (key,status,scopeable,allowed_scopes,delegable)
    ON public.permissions TO daleel_f06team01_admin_executor;
GRANT INSERT (id,occurred_at,tenant_id,event_type,outcome,request_id,actor_membership_id,target_staff_user_id,metadata)
    ON public.tenant_staff_security_events TO daleel_f06team01_admin_executor;
GRANT EXECUTE ON FUNCTION public.f06scope_actor_claim(),public.f06scope_effective_scopes(text)
    TO daleel_f06team01_admin_executor;

CREATE FUNCTION public.f06team01_direct_permission(
    p_action text,p_target uuid,p_permission text,p_scope text,p_grant_id uuid,p_audit_id uuid
) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE
    t uuid; m uuid; u uuid; target_user uuid; target_status text;
    scopes text[]; current_version integer; affected integer;
    manager_present boolean; event_name text;
    old_mode text := pg_catalog.current_setting('app.context_mode',true);
    old_tenant text := pg_catalog.current_setting('app.tenant_id',true);
    old_user text := pg_catalog.current_setting('app.user_id',true);
BEGIN
    SELECT actor_tenant,actor_membership,actor_user INTO t,m,u FROM public.f06scope_actor_claim();
    IF t IS NULL OR m IS NULL OR u IS NULL OR p_target IS NULL OR p_target=m
       OR p_permission IS DISTINCT FROM 'leads.view' OR p_scope IS DISTINCT FROM 'SELF'
       OR p_action NOT IN ('GRANT','REVOKE') OR p_grant_id IS NULL OR p_audit_id IS NULL THEN
        RAISE EXCEPTION 'admin action denied' USING ERRCODE='42501';
    END IF;
    PERFORM pg_catalog.set_config('app.context_mode','TENANT',true);
    PERFORM pg_catalog.set_config('app.tenant_id',t::text,true);
    PERFORM pg_catalog.set_config('app.user_id',u::text,true);

    -- NULL means a corrupt authority snapshot, matching EffectivePermissions fail-closed.
    scopes := public.f06scope_effective_scopes('leads.view');
    IF scopes IS NULL THEN
        RAISE EXCEPTION 'admin authority snapshot denied' USING ERRCODE='42501';
    END IF;
    SELECT EXISTS (
        SELECT 1 FROM public.tenant_staff_membership_roles mr
        JOIN public.roles r ON r.tenant_id=mr.tenant_id AND r.id=mr.role_id
        JOIN public.role_permissions rp ON rp.tenant_id=r.tenant_id AND rp.role_id=r.id
        JOIN public.permissions p ON p.key=rp.permission_key
        WHERE mr.tenant_id=t AND mr.membership_id=m AND mr.revoked_at IS NULL
          AND r.status='ACTIVE' AND r.archived_at IS NULL
          AND rp.permission_key='member.manage' AND rp.scope IS NULL
          AND p.status='ACTIVE' AND p.scopeable=false AND p.allowed_scopes='[]'::jsonb
        UNION ALL
        SELECT 1 FROM public.tenant_staff_permission_grants dg
        JOIN public.permissions p ON p.key=dg.permission_key
        WHERE dg.tenant_id=t AND dg.membership_id=m AND dg.revoked_at IS NULL
          AND dg.permission_key='member.manage' AND dg.scope IS NULL
          AND p.status='ACTIVE' AND p.scopeable=false AND p.allowed_scopes='[]'::jsonb
          AND p.delegable=true
    ) INTO manager_present;
    IF NOT manager_present THEN
        RAISE EXCEPTION 'member manage denied' USING ERRCODE='42501';
    END IF;
    SELECT ms.staff_user_id,ms.status INTO target_user,target_status
    FROM public.tenant_staff_memberships ms
    WHERE ms.tenant_id=t AND ms.id=p_target FOR UPDATE;
    IF target_user IS NULL OR (p_action='GRANT' AND target_status<>'ACTIVE') THEN
        RAISE EXCEPTION 'target unavailable' USING ERRCODE='42501';
    END IF;
    IF p_action='GRANT' THEN
        IF NOT ('SELF'=ANY(scopes) OR 'ALL_TENANT'=ANY(scopes))
           OR NOT EXISTS (SELECT 1 FROM public.permissions p
                          WHERE p.key='leads.view' AND p.status='ACTIVE'
                            AND p.scopeable=true AND p.delegable=true
                            AND p.allowed_scopes @> '["SELF"]'::jsonb) THEN
            RAISE EXCEPTION 'delegation denied' USING ERRCODE='42501';
        END IF;
        INSERT INTO public.tenant_staff_permission_grants
          (id,tenant_id,membership_id,permission_key,scope,granted_by_membership_id,granted_at,created_at,updated_at)
        VALUES (p_grant_id,t,p_target,'leads.view','SELF',m,pg_catalog.now(),pg_catalog.now(),pg_catalog.now());
        event_name := 'tenant_staff.permission_granted';
    ELSE
        UPDATE public.tenant_staff_permission_grants
        SET revoked_at=pg_catalog.now(),revoked_by_membership_id=m,updated_at=pg_catalog.now()
        WHERE tenant_id=t AND membership_id=p_target AND permission_key='leads.view'
          AND scope='SELF' AND revoked_at IS NULL;
        GET DIAGNOSTICS affected = ROW_COUNT;
        IF affected<>1 THEN
            RAISE EXCEPTION 'active grant unavailable' USING ERRCODE='42501';
        END IF;
        event_name := 'tenant_staff.permission_revoked';
    END IF;
    UPDATE public.tenant_staff_memberships
    SET authorization_version=authorization_version+1,updated_at=pg_catalog.now()
    WHERE tenant_id=t AND id=p_target RETURNING authorization_version INTO current_version;
    IF current_version IS NULL THEN
        RAISE EXCEPTION 'version update unavailable' USING ERRCODE='42501';
    END IF;
    INSERT INTO public.tenant_staff_security_events
      (id,occurred_at,tenant_id,event_type,outcome,request_id,actor_membership_id,target_staff_user_id,metadata)
    VALUES (p_audit_id,pg_catalog.now(),t,event_name,'SUCCESS',NULL,m,target_user,'{}'::jsonb);
    PERFORM pg_catalog.set_config('app.context_mode',coalesce(old_mode,''),true);
    PERFORM pg_catalog.set_config('app.tenant_id',coalesce(old_tenant,''),true);
    PERFORM pg_catalog.set_config('app.user_id',coalesce(old_user,''),true);
    RETURN current_version;
END;
$fn$;
ALTER FUNCTION public.f06team01_direct_permission(text,uuid,text,text,uuid,uuid)
    OWNER TO daleel_f06team01_admin_executor;
REVOKE ALL ON FUNCTION public.f06team01_direct_permission(text,uuid,text,text,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06team01_direct_permission(text,uuid,text,text,uuid,uuid)
    TO daleel_f06scope_actor_runtime;
COMMIT;
