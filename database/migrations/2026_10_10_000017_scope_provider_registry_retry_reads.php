<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_provider_select ON tenant_hostnames FOR SELECT
            TO daleel_provider_registry_writer
            USING (
                app_provider_control_tenant_allowed(tenant_id)
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND EXISTS (
                    SELECT 1 FROM provider_control_operations o
                    WHERE o.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND o.action_key = 'company.provision'
                      AND o.target_tenant_id = tenant_hostnames.tenant_id
                      AND o.canonical_slug = tenant_hostnames.tenant_slug
                )
            )
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Provider retry lookup remains scoped to the approved tenant; use a reviewed forward correction.');
    }
};
