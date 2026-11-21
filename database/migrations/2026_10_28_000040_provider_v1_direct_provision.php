<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Direct V1 bootstrap. Old approval rows and policies remain usable by their existing routes. */
return new class extends Migration
{
    public function up(): void
    {
        $old = DB::selectOne("SELECT with_check FROM pg_policies WHERE schemaname = 'public' AND tablename = 'tenants' AND policyname = 'tenants_provider_approved_slug_insert'");
        if (! $old || ! is_string($old->with_check)
            || ! str_contains($old->with_check, 'app_provider_control_tenant_allowed(id)')
            || str_contains($old->with_check, 'core01_v1_allowed')) {
            throw new RuntimeException('The preexisting approved-slug policy is not the expected baseline.');
        }
        $last = DB::selectOne("SELECT count(*) AS n FROM public.tenants WHERE slug IN ('platform', 'legacy')");
        if ((int) $last->n !== 0) {
            throw new RuntimeException('Reserved platform/legacy tenant slug exists.');
        }

        DB::statement("ALTER TABLE public.tenants DROP CONSTRAINT tenants_slug_not_reserved_check");
        DB::statement("ALTER TABLE public.tenants ADD CONSTRAINT tenants_slug_not_reserved_check CHECK (slug !~ '^(admin|api|assets|auth|billing|cdn|docs|help|legacy|mail|marketing|platform|root|static|status|superadmin|support|www)$')");
        DB::statement("ALTER TABLE public.tenant_staff_users DROP CONSTRAINT tenant_staff_status_check");
        DB::statement("ALTER TABLE public.tenant_staff_users ADD CONSTRAINT tenant_staff_status_check CHECK (status IN ('ACTIVE','DISABLED','PENDING_FIRST_PASSWORD_CHANGE'))");

        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_v1_allowed(candidate_tenant uuid) RETURNS boolean
            LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog
            AS $fn$
            BEGIN
                IF session_user <> 'dl_provider_ctl' OR current_user <> 'daleel_b10b_owner'
                   OR current_setting('app.context_mode', true) <> 'CORE01_PROVIDER_V1'
                   OR current_setting('app.core01_v1_operation_id', true) IS NULL
                   OR NOT pg_catalog.pg_input_is_valid(current_setting('app.core01_v1_operation_id', true), 'uuid') THEN
                    RETURN false;
                END IF;
                RETURN EXISTS (
                    SELECT 1 FROM public.provider_control_operations o
                    WHERE o.id = current_setting('app.core01_v1_operation_id', true)::uuid
                      AND o.target_tenant_id = candidate_tenant
                      AND o.requester_provider_user_id = current_setting('app.provider_user_id', true)::uuid
                      AND o.action_key = 'company.provision' AND o.status = 'READY'
                      AND o.approval_request_id IS NULL AND o.ticket_reference = 'CORE01V1'
                );
            END
            $fn$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION public.core01_v1_allowed(uuid) FROM PUBLIC');
        // Existing public RLS policies call this invoker helper. Unauthorized callers
        // return false before it queries the operation table; no definer privilege exists.
        DB::statement('GRANT EXECUTE ON FUNCTION public.core01_v1_allowed(uuid) TO PUBLIC');

        DB::statement('ALTER POLICY tenants_provider_approved_slug_insert ON public.tenants WITH CHECK (('.$old->with_check.') OR (public.core01_v1_allowed(id) AND status = \'ACTIVE\'))');
        DB::statement("CREATE POLICY tenants_core01_v1_insert ON public.tenants FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(id) AND status = 'ACTIVE')");
        DB::statement("CREATE POLICY tenant_hostnames_core01_v1_insert ON public.tenant_hostnames FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id) AND hostname = tenant_slug || '.' || base_domain AND EXISTS (SELECT 1 FROM public.tenant_registry_domains d WHERE d.base_domain = tenant_hostnames.base_domain AND d.mapping_version = tenant_hostnames.mapping_version AND d.is_active))");
        DB::statement("CREATE POLICY tenant_staff_users_core01_v1_insert ON public.tenant_staff_users FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id) AND status = 'PENDING_FIRST_PASSWORD_CHANGE' AND auth_version = 1)");
        DB::statement("CREATE POLICY tenant_staff_memberships_core01_v1_insert ON public.tenant_staff_memberships FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id) AND status = 'ACTIVE' AND created_by_provider_operation_id = current_setting('app.core01_v1_operation_id', true)::uuid)");
        DB::statement("CREATE POLICY roles_core01_v1_insert ON public.roles FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id) AND normalized_name = 'company_admin' AND status = 'ACTIVE' AND version = 1)");
        DB::statement("CREATE POLICY role_permissions_core01_v1_insert ON public.role_permissions FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id))");
        DB::statement("CREATE POLICY tenant_staff_membership_roles_core01_v1_insert ON public.tenant_staff_membership_roles FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id) AND assigned_by_provider_operation_id = current_setting('app.core01_v1_operation_id', true)::uuid AND revoked_at IS NULL)");
        DB::statement("CREATE POLICY tenant_staff_security_events_core01_v1_insert ON public.tenant_staff_security_events FOR INSERT TO PUBLIC WITH CHECK (public.core01_v1_allowed(tenant_id) AND provider_operation_id = current_setting('app.core01_v1_operation_id', true)::uuid AND event_type = 'tenant_staff.created' AND outcome = 'SUCCESS')");
        DB::statement("CREATE POLICY security_audit_events_core01_v1_insert ON public.security_audit_events FOR INSERT TO PUBLIC WITH CHECK (tenant_id IS NOT NULL AND public.core01_v1_allowed(tenant_id) AND event_type = 'tenant.provisioning.executed' AND actor_type = 'PROVIDER_USER' AND source_channel = 'PROVIDER' AND outcome = 'SUCCESS')");

        DB::unprepared(<<<'SQL'
            CREATE FUNCTION public.core01_provision_company_v1(
                p_actor uuid, p_auth_version bigint, p_step_up_at timestamptz,
                p_request_id uuid, p_key_hash text, p_digest text,
                p_display text, p_slug text, p_timezone text, p_email text,
                p_admin_name text, p_password_hash text, p_base_domain text
            ) RETURNS jsonb
            LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
            AS $fn$
            DECLARE
                v_old public.provider_control_operations%ROWTYPE;
                v_operation uuid := pg_catalog.gen_random_uuid();
                v_tenant uuid := pg_catalog.gen_random_uuid();
                v_user uuid := pg_catalog.gen_random_uuid();
                v_membership uuid := pg_catalog.gen_random_uuid();
                v_role uuid := pg_catalog.gen_random_uuid();
                v_template uuid;
                v_host text;
                v_now timestamptz := pg_catalog.transaction_timestamp();
            BEGIN
                IF session_user <> 'dl_provider_ctl'
                   OR p_step_up_at IS NULL OR p_step_up_at > v_now OR p_step_up_at <= v_now - interval '10 minutes'
                   OR NOT EXISTS (
                       SELECT 1 FROM public.provider_users u
                       JOIN public.provider_user_capabilities a ON a.provider_user_id = u.id
                       JOIN public.provider_capabilities c ON c.key = a.capability_key
                       WHERE u.id = p_actor AND u.status = 'ACTIVE'
                         AND u.email_verified_at IS NOT NULL AND u.mfa_enrolled_at IS NOT NULL
                         AND u.auth_version = p_auth_version
                         AND a.capability_key = 'company.provision' AND c.status = 'ACTIVE'
                         AND (a.expires_at IS NULL OR a.expires_at > v_now)
                   ) THEN
                    RAISE EXCEPTION 'provider authorization denied' USING ERRCODE = 'PZ403';
                END IF;
                IF p_key_hash !~ '^[a-f0-9]{64}$' OR p_digest !~ '^[a-f0-9]{64}$'
                   OR p_display IS NULL OR length(btrim(p_display)) NOT BETWEEN 1 AND 160
                   OR p_slug !~ '^[a-z0-9]+(-[a-z0-9]+)*$' OR length(p_slug) > 100
                   OR p_email IS NULL OR p_email <> lower(btrim(p_email)) OR length(p_email) > 254
                   OR p_admin_name IS NULL OR length(btrim(p_admin_name)) NOT BETWEEN 1 AND 160
                   OR p_password_hash NOT LIKE '$argon2id$%'
                   OR p_base_domain IS NULL OR p_base_domain <> lower(p_base_domain)
                   OR NOT EXISTS (SELECT 1 FROM public.tenant_registry_domains d
                       WHERE d.base_domain = p_base_domain AND d.mapping_version = 1 AND d.is_active)
                   OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_timezone_names WHERE name = p_timezone)
                   THEN
                    RAISE EXCEPTION 'invalid provisioning payload' USING ERRCODE = 'PZ422';
                END IF;
                v_host := p_slug || '.' || p_base_domain;
                PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_actor::text || p_key_hash, 0));
                SELECT * INTO v_old FROM public.provider_control_operations o
                WHERE o.requester_provider_user_id = p_actor AND o.action_key = 'company.provision'
                  AND o.idempotency_key_hash = p_key_hash FOR UPDATE;
                IF FOUND THEN
                    IF v_old.ticket_reference <> 'CORE01V1' OR v_old.approval_request_id IS NOT NULL
                       OR v_old.intent_digest <> p_digest OR v_old.status <> 'SUCCEEDED' THEN
                        RAISE EXCEPTION 'idempotency conflict' USING ERRCODE = 'PZ409';
                    END IF;
                    RETURN pg_catalog.jsonb_build_object('operation_id',v_old.id,'tenant_id',v_old.target_tenant_id,
                        'slug',v_old.canonical_slug,'hostname',v_old.canonical_slug || '.' || p_base_domain,
                        'first_admin_state','PENDING_FIRST_PASSWORD_CHANGE','replay',true);
                END IF;
                SELECT t.id INTO v_template FROM public.role_templates t
                WHERE t.code = 'company_admin' AND t.version = 1 AND t.status = 'ACTIVE';
                IF v_template IS NULL OR NOT EXISTS (SELECT 1 FROM public.role_template_permissions tp
                    WHERE tp.template_id = v_template AND tp.permission_key = 'company.administer' AND tp.scope = 'ALL_TENANT') THEN
                    RAISE EXCEPTION 'company administrator template unavailable' USING ERRCODE = 'PZ503';
                END IF;
                INSERT INTO public.provider_control_operations
                    (id,action_key,requester_provider_user_id,approval_request_id,idempotency_key_hash,intent_digest,
                     target_tenant_id,status,display_name,canonical_slug,timezone,founder_email,
                     first_admin_display_name,reason,ticket_reference,expires_at,created_at,updated_at)
                VALUES (v_operation,'company.provision',p_actor,NULL,p_key_hash,p_digest,v_tenant,'READY',
                    p_display,p_slug,p_timezone,p_email,p_admin_name,'V1 direct provision','CORE01V1',
                    v_now + interval '1 day',v_now,v_now);
                PERFORM pg_catalog.set_config('app.context_mode','CORE01_PROVIDER_V1',true);
                PERFORM pg_catalog.set_config('app.core01_v1_operation_id',v_operation::text,true);
                PERFORM pg_catalog.set_config('app.provider_user_id',p_actor::text,true);
                INSERT INTO public.tenants
                    (id,display_name,legal_name,slug,status,timezone,default_locale,archived_at,created_at,updated_at)
                VALUES (v_tenant,p_display,NULL,p_slug,'ACTIVE',p_timezone,'en',NULL,v_now,v_now);
                INSERT INTO public.tenant_hostnames
                    (tenant_id,tenant_slug,base_domain,hostname,mapping_version)
                VALUES (v_tenant,p_slug,p_base_domain,v_host,1);
                INSERT INTO public.tenant_staff_users
                    (id,tenant_id,canonical_email,display_email,display_name,password_hash,status,auth_version,created_at,updated_at)
                VALUES (v_user,v_tenant,p_email,p_email,p_admin_name,p_password_hash,'PENDING_FIRST_PASSWORD_CHANGE',1,v_now,v_now);
                INSERT INTO public.tenant_staff_memberships
                    (id,tenant_id,staff_user_id,status,authorization_version,joined_at,
                     created_by_membership_id,created_by_provider_operation_id,created_at,updated_at)
                VALUES (v_membership,v_tenant,v_user,'ACTIVE',1,v_now,NULL,v_operation,v_now,v_now);
                INSERT INTO public.roles
                    (id,tenant_id,display_name,normalized_name,status,source_template_id,version,archived_at,created_at,updated_at)
                VALUES (v_role,v_tenant,'Company Admin','company_admin','ACTIVE',v_template,1,NULL,v_now,v_now);
                INSERT INTO public.role_permissions(tenant_id,role_id,permission_key,scope)
                SELECT v_tenant,v_role,tp.permission_key,tp.scope FROM public.role_template_permissions tp
                WHERE tp.template_id = v_template;
                INSERT INTO public.tenant_staff_membership_roles
                    (id,tenant_id,membership_id,role_id,assigned_by_membership_id,assigned_by_provider_operation_id,
                     assigned_at,revoked_at,revoked_by_membership_id,created_at,updated_at)
                VALUES (pg_catalog.gen_random_uuid(),v_tenant,v_membership,v_role,NULL,v_operation,v_now,NULL,NULL,v_now,v_now);
                INSERT INTO public.tenant_staff_security_events
                    (id,occurred_at,tenant_id,event_type,outcome,request_id,actor_membership_id,
                     provider_operation_id,target_staff_user_id,metadata)
                VALUES (pg_catalog.gen_random_uuid(),v_now,v_tenant,'tenant_staff.created','SUCCESS',p_request_id,
                    NULL,v_operation,v_user,'{}'::jsonb);
                INSERT INTO public.security_audit_events
                    (id,occurred_at,category,event_type,outcome,request_id,actor_type,actor_id,tenant_id,
                     target_type,target_id,source_channel,operation_id,metadata)
                VALUES (pg_catalog.gen_random_uuid(),v_now,'PROVIDER_SECURITY','tenant.provisioning.executed',
                    'SUCCESS',p_request_id,'PROVIDER_USER',p_actor,v_tenant,'tenant',v_tenant::text,
                    'PROVIDER',v_operation,'{}'::jsonb);
                UPDATE public.provider_control_operations SET status='SUCCEEDED',result_reference=v_tenant,
                    completed_at=v_now,updated_at=v_now WHERE id=v_operation;
                RETURN pg_catalog.jsonb_build_object('operation_id',v_operation,'tenant_id',v_tenant,
                    'slug',p_slug,'hostname',v_host,'first_admin_state','PENDING_FIRST_PASSWORD_CHANGE','replay',false);
            END
            $fn$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION public.core01_provision_company_v1(uuid,bigint,timestamptz,uuid,text,text,text,text,text,text,text,text,text) FROM PUBLIC');
        DB::statement('GRANT EXECUTE ON FUNCTION public.core01_provision_company_v1(uuid,bigint,timestamptz,uuid,text,text,text,text,text,text,text,text,text) TO dl_provider_ctl');
    }

    public function down(): void
    {
        throw new RuntimeException('Core01 V1 direct authority is forward-only; reversing it requires a reviewed data migration.');
    }
};
