<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('tenant_registry_domains', function (Blueprint $table): void {
            $table->smallInteger('mapping_version')->primary();
            $table->string('base_domain', 253);
            // DBA-provisioned classification; never an app-callable environment switch.
            $table->string('environment_scope', 16)->default('NON_LOCAL');
            $table->boolean('is_active')->default(false);
            $table->timestampTz('created_at')->useCurrent();
            $table->unique(['base_domain', 'mapping_version'], 'tenant_registry_domain_identity_unique');
        });
        DB::statement("ALTER TABLE tenant_registry_domains ADD CONSTRAINT tenant_registry_domain_version_check CHECK (mapping_version = 1)");
        DB::statement("ALTER TABLE tenant_registry_domains ADD CONSTRAINT tenant_registry_domain_name_check CHECK (length(base_domain) BETWEEN 3 AND 253 AND base_domain !~ '^[0-9.]+$' AND base_domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' AND split_part(base_domain, '.', array_length(string_to_array(base_domain, '.'), 1)) ~ '[a-z]')");
        DB::statement("ALTER TABLE tenant_registry_domains ADD CONSTRAINT tenant_registry_environment_scope_check CHECK ((environment_scope = 'LOCAL_TEST' AND base_domain LIKE '%.localhost') OR (environment_scope = 'NON_LOCAL' AND base_domain NOT LIKE '%.localhost'))");
        DB::statement('CREATE UNIQUE INDEX tenant_registry_single_active_domain ON tenant_registry_domains ((is_active)) WHERE is_active');

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_tenant_registry_domain_guard() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'Registry domain versions are retained'
                        USING ERRCODE = '23514';
                END IF;
                IF NEW.mapping_version IS DISTINCT FROM OLD.mapping_version
                   OR NEW.base_domain IS DISTINCT FROM OLD.base_domain
                   OR NEW.environment_scope IS DISTINCT FROM OLD.environment_scope THEN
                    RAISE EXCEPTION 'Registry domain identity is immutable'
                        USING ERRCODE = '23514';
                END IF;
                RETURN NEW;
            END
            $$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION app_tenant_registry_domain_guard() FROM PUBLIC');
        DB::statement('CREATE TRIGGER tenant_registry_domains_immutable BEFORE UPDATE OR DELETE ON tenant_registry_domains FOR EACH ROW EXECUTE FUNCTION app_tenant_registry_domain_guard()');
        DB::statement('REVOKE ALL ON TABLE tenant_registry_domains FROM PUBLIC');
        DB::statement('GRANT SELECT ON TABLE tenant_registry_domains TO daleel_provider_registry_writer, daleel_hostname_resolver');

        DB::statement('ALTER TABLE tenant_hostnames ADD CONSTRAINT tenant_hostnames_active_domain_fk FOREIGN KEY (base_domain, mapping_version) REFERENCES tenant_registry_domains(base_domain, mapping_version) ON DELETE RESTRICT NOT VALID');

        DB::statement('DROP POLICY tenant_hostnames_provider_insert ON tenant_hostnames');
        DB::statement('DROP POLICY tenant_hostnames_provider_select ON tenant_hostnames');
        DB::statement('DROP POLICY tenant_hostnames_host_lookup ON tenant_hostnames');
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
                AND EXISTS (
                    SELECT 1 FROM tenant_registry_domains d
                    WHERE d.mapping_version = tenant_hostnames.mapping_version
                      AND d.base_domain = tenant_hostnames.base_domain
                      AND d.is_active
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
                AND EXISTS (
                    SELECT 1 FROM tenant_registry_domains d
                    WHERE d.mapping_version = tenant_hostnames.mapping_version
                      AND d.base_domain = tenant_hostnames.base_domain
                      AND d.is_active
                )
            )
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_host_lookup ON tenant_hostnames FOR SELECT
            TO daleel_hostname_resolver
            USING (
                current_setting('app.context_mode', true) = 'HOST_RESOLUTION'
                AND hostname = current_setting('app.host_resolution_hostname', true)
                AND EXISTS (
                    SELECT 1 FROM tenant_registry_domains d
                    WHERE d.mapping_version = tenant_hostnames.mapping_version
                      AND d.base_domain = tenant_hostnames.base_domain
                      AND d.is_active
                )
            )
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('The active registry domain is an authority boundary; use a reviewed forward correction.');
    }
};
