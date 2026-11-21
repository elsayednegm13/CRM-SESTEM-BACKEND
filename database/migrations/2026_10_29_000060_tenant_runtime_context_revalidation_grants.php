<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Exact columns used by TenantStaffContextGuard after signed authority binding. */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared('GRANT SELECT (id,status) ON public.tenants TO daleel_tenant_runtime');
        DB::unprepared('GRANT SELECT (id,tenant_id,status,auth_version) ON public.tenant_staff_users TO daleel_tenant_runtime');
        DB::unprepared('GRANT SELECT (id,tenant_id,staff_user_id,status,authorization_version) ON public.tenant_staff_memberships TO daleel_tenant_runtime');
    }

    public function down(): void
    {
        throw new RuntimeException('Tenant context revalidation grants are forward-only.');
    }
};
