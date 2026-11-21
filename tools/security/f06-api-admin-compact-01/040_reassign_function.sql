-- Sandbox-only qualified mutation. The actor has no direct UPDATE on assignment.
BEGIN;
CREATE ROLE daleel_f06scope_assigner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO daleel_f06scope_assigner;
GRANT SELECT (id, tenant_id, assigned_membership_id) ON public.leads TO daleel_f06scope_assigner;
GRANT UPDATE (assigned_membership_id, updated_at) ON public.leads TO daleel_f06scope_assigner;
GRANT SELECT (id, tenant_id, status) ON public.tenant_staff_memberships TO daleel_f06scope_assigner;
GRANT EXECUTE ON FUNCTION public.f06scope_actor_claim(),public.f06scope_effective_scopes(text) TO daleel_f06scope_assigner;

CREATE FUNCTION public.f06scope_assign_lead(p_lead uuid,p_target uuid)
RETURNS uuid LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE t uuid; m uuid; u uuid; scopes text[]; matched uuid;
    old_mode text := pg_catalog.current_setting('app.context_mode',true);
    old_tenant text := pg_catalog.current_setting('app.tenant_id',true);
    old_user text := pg_catalog.current_setting('app.user_id',true);
BEGIN
    SELECT actor_tenant,actor_membership,actor_user INTO t,m,u FROM public.f06scope_actor_claim();
    scopes := public.f06scope_effective_scopes('leads.manage');
    IF t IS NULL OR m IS NULL OR p_lead IS NULL OR p_target IS NULL
       OR scopes IS NULL OR NOT 'ALL_TENANT'=ANY(scopes) THEN
        RAISE EXCEPTION 'actor is not authorized to reassign a lead' USING ERRCODE='42501';
    END IF;
    PERFORM pg_catalog.set_config('app.context_mode','TENANT',true);
    PERFORM pg_catalog.set_config('app.tenant_id',t::text,true);
    PERFORM pg_catalog.set_config('app.user_id',u::text,true);
    SELECT l.id INTO matched FROM public.leads l
    WHERE l.tenant_id=t AND l.id=p_lead FOR UPDATE;
    IF matched IS NULL OR NOT EXISTS (
        SELECT 1 FROM public.tenant_staff_memberships target
        WHERE target.tenant_id=t AND target.id=p_target AND target.status='ACTIVE'
    ) THEN
        RAISE EXCEPTION 'lead or target membership unavailable' USING ERRCODE='42501';
    END IF;
    UPDATE public.leads SET assigned_membership_id=p_target,updated_at=pg_catalog.now()
    WHERE tenant_id=t AND id=matched;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'lead update unavailable' USING ERRCODE='42501';
    END IF;
    PERFORM pg_catalog.set_config('app.context_mode',coalesce(old_mode,''),true);
    PERFORM pg_catalog.set_config('app.tenant_id',coalesce(old_tenant,''),true);
    PERFORM pg_catalog.set_config('app.user_id',coalesce(old_user,''),true);
    RETURN matched;
END;
$fn$;
ALTER FUNCTION public.f06scope_assign_lead(uuid,uuid) OWNER TO daleel_f06scope_assigner;
REVOKE ALL ON FUNCTION public.f06scope_assign_lead(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.f06scope_assign_lead(uuid,uuid) TO daleel_f06scope_actor_runtime;
COMMIT;
