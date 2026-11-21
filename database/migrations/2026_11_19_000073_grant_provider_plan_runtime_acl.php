<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Restore the object ACL required by the existing provider plan and subscription services.
 *
 * The PHP boundary still requires an active provider session, the matching capability and
 * step-up for mutations.  FORCE RLS remains authoritative for tenant-owned subscription rows.
 */
return new class extends Migration
{
    public function up(): void
    {
        DB::unprepared(<<<'SQL'
            DO $provider_plan_acl$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_roles
                    WHERE rolname = 'dl_provider'
                      AND NOT rolsuper AND NOT rolcreaterole AND NOT rolbypassrls
                ) THEN
                    RAISE EXCEPTION 'dl_provider least-privilege role contract is missing';
                END IF;
            END
            $provider_plan_acl$;

            REVOKE ALL PRIVILEGES ON plans, plan_limits, tenant_subscriptions, tenant_limit_overrides FROM dl_provider;
            GRANT SELECT, INSERT, UPDATE ON plans TO dl_provider;
            GRANT SELECT, INSERT, UPDATE ON plan_limits TO dl_provider;
            GRANT SELECT, INSERT, UPDATE ON tenant_subscriptions TO dl_provider;
            GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_limit_overrides TO dl_provider;
        SQL);
    }

    public function down(): void
    {
        throw new RuntimeException('Forward-only security migration.');
    }
};
