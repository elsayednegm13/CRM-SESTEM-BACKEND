<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    private const TENANT_TABLES = ['roles', 'role_permissions', 'membership_roles'];

    public function up(): void
    {
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_rls_context_mode() RETURNS text
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT CASE WHEN current_setting('app.context_mode', true) IN ('TENANT_DISCOVERY', 'TENANT')
                    THEN current_setting('app.context_mode', true) ELSE NULL END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_rls_current_user_id() RETURNS uuid
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT CASE WHEN pg_input_is_valid(NULLIF(current_setting('app.user_id', true), ''), 'uuid')
                    THEN current_setting('app.user_id', true)::uuid ELSE NULL END
            $$
        SQL);
        DB::statement(<<<'SQL'
            CREATE OR REPLACE FUNCTION app_rls_current_tenant_id() RETURNS uuid
            LANGUAGE sql STABLE SECURITY INVOKER
            AS $$
                SELECT CASE WHEN pg_input_is_valid(NULLIF(current_setting('app.tenant_id', true), ''), 'uuid')
                    THEN current_setting('app.tenant_id', true)::uuid ELSE NULL END
            $$
        SQL);

        foreach (['tenants', 'tenant_memberships', ...self::TENANT_TABLES] as $table) {
            DB::statement("ALTER TABLE {$table} ENABLE ROW LEVEL SECURITY");
            DB::statement("ALTER TABLE {$table} FORCE ROW LEVEL SECURITY");
        }

        DB::statement(<<<'SQL'
            CREATE POLICY tenants_tenant_select ON tenants FOR SELECT
            USING (app_rls_context_mode() = 'TENANT' AND id = app_rls_current_tenant_id())
        SQL);
        DB::statement(<<<'SQL'
            CREATE POLICY tenants_tenant_update ON tenants FOR UPDATE
            USING (app_rls_context_mode() = 'TENANT' AND id = app_rls_current_tenant_id())
            WITH CHECK (app_rls_context_mode() = 'TENANT' AND id = app_rls_current_tenant_id())
        SQL);

        DB::statement(<<<'SQL'
            CREATE POLICY tenant_memberships_context_select ON tenant_memberships FOR SELECT
            USING (
                (app_rls_context_mode() = 'TENANT_DISCOVERY'
                    AND user_id = app_rls_current_user_id() AND status = 'ACTIVE')
                OR (app_rls_context_mode() = 'TENANT'
                    AND tenant_id = app_rls_current_tenant_id())
            )
        SQL);
        foreach (['INSERT', 'UPDATE', 'DELETE'] as $command) {
            $using = $command === 'INSERT' ? '' : "USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())";
            $check = $command === 'DELETE' ? '' : "WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())";
            DB::statement("CREATE POLICY tenant_memberships_tenant_".strtolower($command)
                ." ON tenant_memberships FOR {$command} {$using} {$check}");
        }

        foreach (self::TENANT_TABLES as $table) {
            DB::statement("CREATE POLICY {$table}_tenant_select ON {$table} FOR SELECT "
                ."USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())");
            foreach (['INSERT', 'UPDATE', 'DELETE'] as $command) {
                $using = $command === 'INSERT' ? '' : "USING (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())";
                $check = $command === 'DELETE' ? '' : "WITH CHECK (app_rls_context_mode() = 'TENANT' AND tenant_id = app_rls_current_tenant_id())";
                DB::statement("CREATE POLICY {$table}_tenant_".strtolower($command)
                    ." ON {$table} FOR {$command} {$using} {$check}");
            }
        }
    }

    public function down(): void
    {
        foreach (self::TENANT_TABLES as $table) {
            foreach (['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as $command) {
                DB::statement("DROP POLICY {$table}_tenant_".strtolower($command)." ON {$table}");
            }
        }
        DB::statement('DROP POLICY tenant_memberships_context_select ON tenant_memberships');
        foreach (['INSERT', 'UPDATE', 'DELETE'] as $command) {
            DB::statement('DROP POLICY tenant_memberships_tenant_'.strtolower($command).' ON tenant_memberships');
        }
        DB::statement('DROP POLICY tenants_tenant_select ON tenants');
        DB::statement('DROP POLICY tenants_tenant_update ON tenants');
        foreach (['tenants', 'tenant_memberships', ...self::TENANT_TABLES] as $table) {
            DB::statement("ALTER TABLE {$table} NO FORCE ROW LEVEL SECURITY");
            DB::statement("ALTER TABLE {$table} DISABLE ROW LEVEL SECURITY");
        }
        DB::statement('DROP FUNCTION app_rls_current_tenant_id()');
        DB::statement('DROP FUNCTION app_rls_current_user_id()');
        DB::statement('DROP FUNCTION app_rls_context_mode()');
    }
};
