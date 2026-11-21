<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Least-privilege write contract for the tenant-staff runtime group (DEV-FOUNDATION-01 /
 * REMEDIATION-03, finding F05). Column-level grants match exactly what the Phase 2 services
 * issue over pgsql_tenant_runtime; RLS policies, triggers and FORCE RLS are unchanged.
 * tenant_id is never updatable, password_hash is insert-only, audit events are insert-only,
 * and role_permissions is the only table with DELETE (role grant replacement).
 */
return new class extends Migration
{
    private const GRANTS = [
        'GRANT SELECT (version) ON public.roles TO daleel_tenant_runtime',
        'GRANT INSERT (id, tenant_id, display_name, normalized_name, created_at, updated_at) ON public.roles TO daleel_tenant_runtime',
        'GRANT UPDATE (status, archived_at, version, updated_at) ON public.roles TO daleel_tenant_runtime',

        'GRANT INSERT (tenant_id, role_id, permission_key, scope) ON public.role_permissions TO daleel_tenant_runtime',
        'GRANT DELETE ON public.role_permissions TO daleel_tenant_runtime',

        'GRANT INSERT (id, tenant_id, canonical_email, display_email, display_name, password_hash, status, auth_version, created_at, updated_at) ON public.tenant_staff_users TO daleel_tenant_runtime',

        'GRANT SELECT (joined_at, created_by_membership_id, created_by_provider_operation_id, created_at, updated_at) ON public.tenant_staff_memberships TO daleel_tenant_runtime',
        'GRANT INSERT (id, tenant_id, staff_user_id, status, authorization_version, joined_at, created_by_membership_id, created_by_provider_operation_id, created_at, updated_at) ON public.tenant_staff_memberships TO daleel_tenant_runtime',
        'GRANT UPDATE (status, authorization_version, updated_at) ON public.tenant_staff_memberships TO daleel_tenant_runtime',

        'GRANT SELECT (id, assigned_by_membership_id, assigned_by_provider_operation_id, assigned_at, revoked_by_membership_id, created_at, updated_at) ON public.tenant_staff_membership_roles TO daleel_tenant_runtime',
        'GRANT INSERT (id, tenant_id, membership_id, role_id, assigned_by_membership_id, assigned_by_provider_operation_id, assigned_at, created_at, updated_at) ON public.tenant_staff_membership_roles TO daleel_tenant_runtime',
        'GRANT UPDATE (revoked_at, revoked_by_membership_id, updated_at) ON public.tenant_staff_membership_roles TO daleel_tenant_runtime',

        'GRANT INSERT (id, tenant_id, membership_id, permission_key, scope, granted_by_membership_id, granted_at, created_at, updated_at) ON public.tenant_staff_permission_grants TO daleel_tenant_runtime',
        'GRANT UPDATE (revoked_at, revoked_by_membership_id, updated_at) ON public.tenant_staff_permission_grants TO daleel_tenant_runtime',

        'GRANT INSERT (id, occurred_at, tenant_id, event_type, outcome, request_id, actor_membership_id, provider_operation_id, target_staff_user_id, target_role_id, metadata) ON public.tenant_staff_security_events TO daleel_tenant_runtime',

        'GRANT SELECT (id, tenant_id, name, phone, email, city, country, source, campaign, pipeline_stage, interest_level, estimated_value_minor, status, assigned_membership_id, created_by_membership_id, last_contacted_at, created_at, updated_at) ON public.leads TO daleel_tenant_runtime',
        'GRANT INSERT (id, tenant_id, name, phone, email, city, country, source, campaign, pipeline_stage, interest_level, estimated_value_minor, status, assigned_membership_id, created_by_membership_id, last_contacted_at, created_at, updated_at) ON public.leads TO daleel_tenant_runtime',
        'GRANT UPDATE (name, phone, email, city, country, source, campaign, pipeline_stage, interest_level, estimated_value_minor, status, assigned_membership_id, last_contacted_at, updated_at) ON public.leads TO daleel_tenant_runtime',
    ];

    public function up(): void
    {
        DB::statement(<<<'SQL'
            DO $guard$
            DECLARE runtime pg_catalog.pg_roles%ROWTYPE;
            BEGIN
                SELECT * INTO runtime FROM pg_catalog.pg_roles WHERE rolname = 'daleel_tenant_runtime';
                IF NOT FOUND OR runtime.rolcanlogin OR runtime.rolsuper OR runtime.rolbypassrls
                   OR runtime.rolcreatedb OR runtime.rolcreaterole THEN
                    RAISE EXCEPTION 'daleel_tenant_runtime must exist as a NOLOGIN least-privilege group'
                        USING ERRCODE = '55000';
                END IF;
                IF pg_catalog.has_schema_privilege('daleel_tenant_runtime', 'public', 'CREATE')
                   OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                              WHERE n.nspname = 'public' AND c.relowner = runtime.oid) THEN
                    RAISE EXCEPTION 'daleel_tenant_runtime must not own objects or create in schema public'
                        USING ERRCODE = '55000';
                END IF;
            END
            $guard$
        SQL);

        foreach (self::GRANTS as $grant) {
            DB::statement($grant);
        }
    }

    public function down(): void
    {
        throw new LogicException('Runtime ACL migrations are forward-only; use a separately reviewed forward correction.');
    }
};
