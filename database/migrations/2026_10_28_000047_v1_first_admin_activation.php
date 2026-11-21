<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Restricted first-password activation for a directly provisioned V1 founder. */
return new class extends Migration
{
    public function up(): void
    {
        $row = DB::selectOne("SELECT pg_get_functiondef('public.lookup_tenant_staff_credentials(text,text,text,text)'::regprocedure) AS definition");
        if (! is_string($row?->definition)
            || substr_count($row->definition, "staff.status = 'ACTIVE'") !== 1
            || ! str_contains($row->definition, 'SECURITY DEFINER')) {
            throw new RuntimeException('Unexpected credential lookup baseline.');
        }
        $lookup = str_replace('public.lookup_tenant_staff_credentials(', 'public.core01_lookup_pending_first_admin(', $row->definition);
        $lookup = str_replace("staff.status = 'ACTIVE'", "staff.status = 'PENDING_FIRST_PASSWORD_CHANGE'", $lookup);
        DB::unprepared($lookup);
        // PostgreSQL requires target-owner CREATE privilege for ALTER OWNER. The
        // grant exists only inside this transactional migration and is revoked.
        DB::unprepared('GRANT CREATE ON SCHEMA public TO daleel_tenant_auth_lookup');
        DB::unprepared('ALTER FUNCTION public.core01_lookup_pending_first_admin(text,text,text,text) OWNER TO daleel_tenant_auth_lookup');
        DB::unprepared('REVOKE CREATE ON SCHEMA public FROM daleel_tenant_auth_lookup');
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_lookup_pending_first_admin(text,text,text,text) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_lookup_pending_first_admin(text,text,text,text) TO daleel_tenant_auth_client');

        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_activation_allowed(candidate_tenant uuid) RETURNS boolean
            LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog
            AS $fn$
            BEGIN
                IF session_user <> 'dl_onboarding' OR current_user <> 'daleel_b10b_owner'
                   OR current_setting('app.context_mode', true) <> 'CORE01_FIRST_ADMIN_ACTIVATION'
                   OR NOT pg_catalog.pg_input_is_valid(current_setting('app.core01_v1_operation_id', true), 'uuid') THEN
                    RETURN false;
                END IF;
                RETURN EXISTS (
                    SELECT 1 FROM public.provider_control_operations o
                    WHERE o.id = current_setting('app.core01_v1_operation_id', true)::uuid
                      AND o.target_tenant_id = candidate_tenant
                      AND o.action_key = 'company.provision' AND o.status = 'SUCCEEDED'
                      AND o.approval_request_id IS NULL AND o.ticket_reference = 'CORE01V1'
                );
            END
            $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_activation_allowed(uuid) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_activation_allowed(uuid) TO PUBLIC');
        DB::unprepared("CREATE POLICY tenant_staff_users_core01_activation_select ON public.tenant_staff_users FOR SELECT TO daleel_b10b_owner USING (public.core01_activation_allowed(tenant_id))");
        DB::unprepared("CREATE POLICY tenant_staff_users_core01_activation_update ON public.tenant_staff_users FOR UPDATE TO daleel_b10b_owner USING (public.core01_activation_allowed(tenant_id) AND status = 'PENDING_FIRST_PASSWORD_CHANGE') WITH CHECK (public.core01_activation_allowed(tenant_id) AND status = 'ACTIVE')");
        DB::unprepared("CREATE POLICY tenant_staff_memberships_core01_activation_select ON public.tenant_staff_memberships FOR SELECT TO daleel_b10b_owner USING (public.core01_activation_allowed(tenant_id))");
        DB::unprepared("CREATE POLICY roles_core01_activation_select ON public.roles FOR SELECT TO daleel_b10b_owner USING (public.core01_activation_allowed(tenant_id))");
        DB::unprepared("CREATE POLICY tenant_staff_membership_roles_core01_activation_insert ON public.tenant_staff_membership_roles FOR INSERT TO daleel_b10b_owner WITH CHECK (public.core01_activation_allowed(tenant_id) AND assigned_by_provider_operation_id = nullif(current_setting('app.core01_v1_operation_id',true),'')::uuid AND revoked_at IS NULL)");
        DB::unprepared("CREATE POLICY tenant_staff_security_events_core01_activation_insert ON public.tenant_staff_security_events FOR INSERT TO daleel_b10b_owner WITH CHECK (public.core01_activation_allowed(tenant_id) AND event_type = 'tenant_staff.password_set' AND outcome = 'SUCCESS' AND provider_operation_id = nullif(current_setting('app.core01_v1_operation_id',true),'')::uuid)");

        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_activate_first_admin(
                p_tenant uuid, p_user uuid, p_membership uuid,
                p_old_hash text, p_new_hash text, p_hostname text, p_request_id uuid
            ) RETURNS boolean
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public
            AS $fn$
            DECLARE
                v_operation public.provider_control_operations%ROWTYPE;
                v_staff public.tenant_staff_users%ROWTYPE;
                v_membership public.tenant_staff_memberships%ROWTYPE;
                v_role uuid;
                v_now timestamptz := pg_catalog.clock_timestamp();
            BEGIN
                IF session_user <> 'dl_onboarding' OR p_old_hash IS NULL OR p_new_hash NOT LIKE '$argon2id$%'
                   OR p_old_hash = p_new_hash OR p_request_id IS NULL THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT * INTO v_operation FROM public.provider_control_operations o
                WHERE o.target_tenant_id = p_tenant AND o.action_key = 'company.provision'
                  AND o.status = 'SUCCEEDED' AND o.ticket_reference = 'CORE01V1'
                  AND o.approval_request_id IS NULL FOR UPDATE;
                IF NOT FOUND OR p_hostname <> v_operation.canonical_slug || '.' || current_setting('app.core01_base_domain', true) THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                PERFORM pg_catalog.set_config('app.context_mode','CORE01_FIRST_ADMIN_ACTIVATION',true);
                PERFORM pg_catalog.set_config('app.core01_v1_operation_id',v_operation.id::text,true);
                SELECT * INTO v_staff FROM public.tenant_staff_users u
                WHERE u.tenant_id = p_tenant AND u.id = p_user FOR UPDATE;
                IF NOT FOUND OR v_staff.status <> 'PENDING_FIRST_PASSWORD_CHANGE'
                   OR v_staff.auth_version <> 1 OR v_staff.canonical_email <> v_operation.founder_email
                   OR v_staff.password_hash <> p_old_hash THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT * INTO v_membership FROM public.tenant_staff_memberships m
                WHERE m.tenant_id = p_tenant AND m.id = p_membership AND m.staff_user_id = p_user;
                IF NOT FOUND OR v_membership.status <> 'ACTIVE'
                   OR v_membership.created_by_provider_operation_id <> v_operation.id THEN
                    RAISE EXCEPTION 'first admin activation denied' USING ERRCODE = 'PZ403';
                END IF;
                SELECT r.id INTO v_role FROM public.roles r
                WHERE r.tenant_id = p_tenant AND r.normalized_name = 'company_admin'
                  AND r.status = 'ACTIVE' AND r.version = 1;
                IF v_role IS NULL THEN
                    RAISE EXCEPTION 'first admin role missing' USING ERRCODE = 'PZ503';
                END IF;
                UPDATE public.tenant_staff_users SET password_hash=p_new_hash,
                    status='ACTIVE',auth_version=auth_version+1,updated_at=v_now
                WHERE tenant_id=p_tenant AND id=p_user;
                INSERT INTO public.tenant_staff_membership_roles
                    (id,tenant_id,membership_id,role_id,assigned_by_membership_id,
                     assigned_by_provider_operation_id,assigned_at,revoked_at,
                     revoked_by_membership_id,created_at,updated_at)
                VALUES (pg_catalog.gen_random_uuid(),p_tenant,p_membership,v_role,NULL,
                    v_operation.id,v_now,NULL,NULL,v_now,v_now);
                INSERT INTO public.tenant_staff_security_events
                    (id,occurred_at,tenant_id,event_type,outcome,request_id,actor_membership_id,
                     provider_operation_id,target_staff_user_id,metadata)
                VALUES (pg_catalog.gen_random_uuid(),v_now,p_tenant,'tenant_staff.password_set',
                    'SUCCESS',p_request_id,NULL,v_operation.id,p_user,'{}'::jsonb);
                RETURN true;
            END
            $fn$
        SQL);
        DB::unprepared('REVOKE ALL ON FUNCTION public.core01_activate_first_admin(uuid,uuid,uuid,text,text,text,uuid) FROM PUBLIC');
        DB::unprepared('GRANT EXECUTE ON FUNCTION public.core01_activate_first_admin(uuid,uuid,uuid,text,text,text,uuid) TO dl_onboarding');
    }

    public function down(): void
    {
        throw new RuntimeException('V1 founder activation is forward-only.');
    }
};
