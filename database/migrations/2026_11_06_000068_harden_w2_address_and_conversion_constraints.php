<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/** Source-only W2 hardening candidate; never executed in this authorization. */
return new class extends Migration
{
    public function up(): void
    {
        // The composite key makes a conversion contact prove its parent customer in the same tenant.
        DB::statement('ALTER TABLE public.customer_contacts ADD CONSTRAINT contacts_tenant_customer_id_unique UNIQUE (tenant_id, customer_id, id)');
        DB::statement('ALTER TABLE public.lead_conversions ADD CONSTRAINT conversions_contact_customer_tenant_fk FOREIGN KEY (tenant_id, customer_id, contact_id) REFERENCES public.customer_contacts (tenant_id, customer_id, id) ON DELETE RESTRICT');

        // 066 granted table-wide address SELECT. Replace it with the exact response fields used by CustomerService.
        DB::statement('REVOKE SELECT ON TABLE public.customer_addresses FROM daleel_tenant_runtime');
        DB::statement('GRANT SELECT (id, tenant_id, customer_id, kind, line1, line2, city, region, postal_code, country_code, created_at, updated_at) ON public.customer_addresses TO daleel_tenant_runtime');
    }

    public function down(): void
    {
        throw new \LogicException('Forward-only W2 hardening migration candidate.');
    }
};
