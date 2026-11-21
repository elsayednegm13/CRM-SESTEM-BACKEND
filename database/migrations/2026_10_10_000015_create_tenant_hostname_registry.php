<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    private const RESERVED_SLUGS = 'admin|api|assets|auth|billing|cdn|docs|help|mail|marketing|root|static|status|superadmin|support|www';

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

        DB::statement('ALTER TABLE tenants ADD CONSTRAINT tenants_id_slug_unique UNIQUE (id, slug)');
        DB::statement("ALTER TABLE tenants ADD CONSTRAINT tenants_slug_not_reserved_check CHECK (slug !~ '^(".self::RESERVED_SLUGS.")$')");

        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_tenant_registry_immutable_guard() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'Tenant registry identities are permanent'
                        USING ERRCODE = '23514';
                END IF;

                IF TG_TABLE_NAME = 'tenants' AND NEW.slug IS DISTINCT FROM OLD.slug THEN
                    RAISE EXCEPTION 'Tenant slugs are immutable'
                        USING ERRCODE = '23514';
                END IF;

                IF TG_TABLE_NAME = 'tenant_hostnames'
                   AND (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                     OR NEW.tenant_slug IS DISTINCT FROM OLD.tenant_slug
                     OR NEW.base_domain IS DISTINCT FROM OLD.base_domain
                     OR NEW.hostname IS DISTINCT FROM OLD.hostname
                     OR NEW.mapping_version IS DISTINCT FROM OLD.mapping_version) THEN
                    RAISE EXCEPTION 'Tenant hostname mappings are immutable'
                        USING ERRCODE = '23514';
                END IF;

                RETURN NEW;
            END
            $$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION app_tenant_registry_immutable_guard() FROM PUBLIC');
        DB::statement('CREATE TRIGGER tenants_registry_immutable BEFORE UPDATE OF slug OR DELETE ON tenants FOR EACH ROW EXECUTE FUNCTION app_tenant_registry_immutable_guard()');

        Schema::create('tenant_hostnames', function (Blueprint $table): void {
            $table->uuid('tenant_id')->primary();
            $table->string('tenant_slug', 100);
            $table->string('base_domain', 253);
            $table->string('hostname', 253)->unique('tenant_hostnames_hostname_unique');
            $table->smallInteger('mapping_version')->default(1);
            $table->timestampTz('created_at')->useCurrent();

            $table->foreign(['tenant_id', 'tenant_slug'], 'tenant_hostnames_tenant_identity_fk')
                ->references(['id', 'slug'])->on('tenants')->restrictOnDelete();
        });

        DB::statement("ALTER TABLE tenant_hostnames ADD CONSTRAINT tenant_hostnames_platform_host_check CHECK (hostname = tenant_slug || '.' || base_domain)");
        DB::statement("ALTER TABLE tenant_hostnames ADD CONSTRAINT tenant_hostnames_base_domain_check CHECK (length(base_domain) BETWEEN 3 AND 253 AND base_domain !~ '^[0-9.]+$' AND base_domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')");
        DB::statement("ALTER TABLE tenant_hostnames ADD CONSTRAINT tenant_hostnames_mapping_version_check CHECK (mapping_version = 1)");
        DB::statement('CREATE TRIGGER tenant_hostnames_immutable BEFORE UPDATE OR DELETE ON tenant_hostnames FOR EACH ROW EXECUTE FUNCTION app_tenant_registry_immutable_guard()');
        DB::statement('ALTER TABLE tenant_hostnames ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE tenant_hostnames FORCE ROW LEVEL SECURITY');
        DB::statement('REVOKE ALL ON TABLE tenant_hostnames FROM PUBLIC');
        DB::statement('GRANT SELECT ON TABLE tenant_hostnames TO daleel_provider_registry_writer, daleel_hostname_resolver');
        DB::statement('GRANT INSERT ON TABLE tenant_hostnames TO daleel_provider_registry_writer');

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_provider_insert ON tenant_hostnames FOR INSERT
            TO daleel_provider_registry_writer
            WITH CHECK (app_provider_control_tenant_allowed(tenant_id)
                AND current_setting('app.provider_action', true) = 'company.provision'
                AND tenant_slug = (SELECT slug FROM tenants WHERE id = tenant_id))
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenant_hostnames_host_lookup ON tenant_hostnames FOR SELECT
            TO daleel_hostname_resolver
            USING (current_setting('app.context_mode', true) = 'HOST_RESOLUTION'
                AND hostname = current_setting('app.host_resolution_hostname', true))
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Tenant slug and hostname reservations are permanent; this migration requires a reviewed forward correction.');
    }
};
