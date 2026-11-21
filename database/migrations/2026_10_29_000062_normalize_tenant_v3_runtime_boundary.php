<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Converges sandboxes where the superseded 061 was recorded administratively. */
return new class extends Migration
{
    public function up(): void
    {
        $tables = [
            'leads', 'membership_roles', 'role_permissions', 'roles', 'security_audit_events',
            'tenant_hostnames', 'tenant_limit_overrides', 'tenant_memberships',
            'tenant_staff_membership_roles', 'tenant_staff_memberships',
            'tenant_staff_password_reset_tokens', 'tenant_staff_permission_grants',
            'tenant_staff_security_events', 'tenant_staff_users', 'tenant_subscriptions', 'tenants',
        ];
        $expression = "array_length(pg_catalog.string_to_array(pg_catalog.current_setting('app.core01_signed_context', true), '|'), 1) = 13 AND pg_catalog.split_part(pg_catalog.current_setting('app.core01_signed_context', true), '|', 12) = 'v3'";
        $existing = DB::select(
            "SELECT tablename, permissive, roles, cmd, qual, with_check FROM pg_policies WHERE schemaname='public' AND policyname='core01_v3_runtime_boundary' ORDER BY tablename"
        );
        if (count($existing) !== 0 && count($existing) !== count($tables)) {
            throw new RuntimeException('Tenant v3 restrictive policy cutover is partial.');
        }
        if (count($existing) === 0) {
            foreach ($tables as $table) {
                DB::unprepared("CREATE POLICY core01_v3_runtime_boundary ON public.{$table} AS RESTRICTIVE FOR ALL TO daleel_tenant_runtime USING ({$expression}) WITH CHECK ({$expression})");
            }
            $existing = DB::select(
                "SELECT tablename, permissive, roles, cmd, qual, with_check FROM pg_policies WHERE schemaname='public' AND policyname='core01_v3_runtime_boundary' ORDER BY tablename"
            );
        }
        foreach ($existing as $index => $policy) {
            if ($policy->tablename !== $tables[$index] || $policy->permissive !== 'RESTRICTIVE'
                || $policy->cmd !== 'ALL' || ! str_contains((string) $policy->roles, 'daleel_tenant_runtime')
                || ! str_contains((string) $policy->qual, "= 13") || ! str_contains((string) $policy->qual, "= 'v3'::text")
                || $policy->qual !== $policy->with_check) {
                throw new RuntimeException('Tenant v3 restrictive policy definition drifted.');
            }
        }
    }

    public function down(): void
    {
        throw new RuntimeException('Tenant v3 boundary normalization is forward-only.');
    }
};
