<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * W2 source-only follow-up to 066. It deliberately changes neither existing
 * RLS policies nor legacy role contracts; it grants only the columns required
 * by the tenant-runtime customer/contact/address API.
 */
return new class extends Migration
{
    public function up(): void
    {
        foreach ([
            'GRANT UPDATE (display_name, email, phone, job_title, note, is_primary, updated_at) ON public.customer_contacts TO daleel_tenant_runtime',
            'GRANT INSERT (id, tenant_id, customer_id, kind, line1, line2, city, region, postal_code, country_code, created_at, updated_at) ON public.customer_addresses TO daleel_tenant_runtime',
            'GRANT UPDATE (kind, line1, line2, city, region, postal_code, country_code, updated_at) ON public.customer_addresses TO daleel_tenant_runtime',
        ] as $statement) {
            DB::statement($statement);
        }
    }

    public function down(): void
    {
        throw new \LogicException('Forward-only W2 migration candidate.');
    }
};
