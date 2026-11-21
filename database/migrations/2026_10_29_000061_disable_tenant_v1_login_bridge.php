<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Forward-only cutover: runtime rows require the durable v3 context shape. */
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

        foreach ($tables as $table) {
            $baseline = DB::selectOne(
                "SELECT permissive, roles, cmd FROM pg_policies WHERE schemaname='public' AND tablename=? AND policyname='core01_signed_runtime_boundary'",
                [$table],
            );
            if (! $baseline || $baseline->permissive !== 'RESTRICTIVE' || $baseline->cmd !== 'ALL'
                || ! str_contains((string) $baseline->roles, 'daleel_tenant_runtime')) {
                throw new RuntimeException("Tenant signed runtime baseline is invalid for {$table}.");
            }
            DB::unprepared("CREATE POLICY core01_v3_runtime_boundary ON public.{$table} AS RESTRICTIVE FOR ALL TO daleel_tenant_runtime USING ({$expression}) WITH CHECK ({$expression})");
        }

        $count = (int) (DB::selectOne(
            "SELECT count(*) AS n FROM pg_policies WHERE schemaname='public' AND policyname='core01_v3_runtime_boundary' AND permissive='RESTRICTIVE' AND cmd='ALL'"
        )->n ?? 0);
        if ($count !== count($tables)) {
            throw new RuntimeException('Tenant v3 restrictive policy cutover is incomplete.');
        }
    }

    public function down(): void
    {
        throw new RuntimeException('Tenant v1 bridge closure is forward-only.');
    }
};
