<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            DO $$
            DECLARE invalid_roles text;
            BEGIN
                SELECT string_agg(required.name, ', ' ORDER BY required.name)
                INTO invalid_roles
                FROM (VALUES ('daleel_provider_registry_writer'), ('daleel_hostname_resolver')) AS required(name)
                LEFT JOIN pg_roles r ON r.rolname = required.name
                WHERE r.rolname IS NULL OR r.rolcanlogin OR r.rolsuper OR r.rolbypassrls;

                IF invalid_roles IS NOT NULL THEN
                    RAISE EXCEPTION 'Required non-login, non-superuser registry roles are absent or unsafe: %', invalid_roles
                        USING ERRCODE = '55000';
                END IF;
            END
            $$
        SQL);

        DB::statement('DROP POLICY tenant_hostnames_provider_insert ON tenant_hostnames');
        DB::statement('DROP POLICY tenant_hostnames_scoped_select ON tenant_hostnames');

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_provider_insert ON tenant_hostnames FOR INSERT
            TO daleel_provider_registry_writer
            WITH CHECK (
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
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_provider_select ON tenant_hostnames FOR SELECT
            TO daleel_provider_registry_writer
            USING (
                current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND app_provider_control_tenant_allowed(tenant_id)
                AND EXISTS (
                    SELECT 1 FROM provider_control_operations o
                    WHERE o.id = app_provider_control_setting_uuid('app.provider_operation_id')
                      AND o.action_key = 'company.provision'
                      AND o.target_tenant_id = tenant_hostnames.tenant_id
                      AND o.canonical_slug = tenant_hostnames.tenant_slug
                )
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_host_lookup ON tenant_hostnames FOR SELECT
            TO daleel_hostname_resolver
            USING (
                current_setting('app.context_mode', true) = 'HOST_RESOLUTION'
                AND hostname = current_setting('app.host_resolution_hostname', true)
            )
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Registry role isolation is a security invariant; use a reviewed forward correction.');
    }
};
