<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_tenant_registry_immutable_guard() RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'Tenant registry identities are permanent'
                        USING ERRCODE = '23514';
                END IF;

                IF TG_TABLE_NAME = 'tenants' THEN
                    IF NEW.slug IS DISTINCT FROM OLD.slug THEN
                        RAISE EXCEPTION 'Tenant slugs are immutable'
                            USING ERRCODE = '23514';
                    END IF;
                ELSIF TG_TABLE_NAME = 'tenant_hostnames' THEN
                    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
                       OR NEW.tenant_slug IS DISTINCT FROM OLD.tenant_slug
                       OR NEW.base_domain IS DISTINCT FROM OLD.base_domain
                       OR NEW.hostname IS DISTINCT FROM OLD.hostname
                       OR NEW.mapping_version IS DISTINCT FROM OLD.mapping_version THEN
                        RAISE EXCEPTION 'Tenant hostname mappings are immutable'
                            USING ERRCODE = '23514';
                    END IF;
                END IF;

                RETURN NEW;
            END
            $$
        SQL);
        DB::statement('REVOKE ALL ON FUNCTION app_tenant_registry_immutable_guard() FROM PUBLIC');
    }

    public function down(): void
    {
        throw new RuntimeException('The corrected tenant identity guard is a security invariant; use a reviewed forward correction.');
    }
};
