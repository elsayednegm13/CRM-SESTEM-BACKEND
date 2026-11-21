<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $control = $this->runtimeRole('pgsql_provider_control');

        DB::transaction(function () use ($control): void {
            DB::statement(<<<'SQL'
                ALTER TABLE provider_provision_revisions
                ADD COLUMN edit_reason_ciphertext text NULL,
                ADD CONSTRAINT provider_provision_revision_reason_ciphertext_check
                    CHECK (edit_reason_ciphertext IS NULL OR
                        (length(edit_reason_ciphertext) BETWEEN 100 AND 8192
                         AND edit_reason_ciphertext ~ '^eyJpdiI6I[A-Za-z0-9+/=]+$'))
            SQL);

            DB::statement('DROP POLICY provider_provision_revision_read ON provider_provision_revisions');
            DB::statement(sprintf(<<<'SQL'
                CREATE POLICY provider_provision_revision_read ON provider_provision_revisions
                FOR SELECT TO %s
                USING (
                    current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                    AND current_setting('app.provider_capability', true) = 'company.provision'
                    AND app_provider_control_actor_allowed()
                    AND requester_provider_user_id = app_provider_control_setting_uuid('app.provider_user_id')
                    AND operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                    AND EXISTS (
                        SELECT 1 FROM provider_control_operations o
                        WHERE o.id = provider_provision_revisions.operation_id
                          AND o.action_key = 'company.provision'
                          AND o.requester_provider_user_id = provider_provision_revisions.requester_provider_user_id
                    )
                )
            SQL, $control));
            DB::statement(sprintf(<<<'SQL'
                CREATE POLICY provider_provision_revision_reviewer_read ON provider_provision_revisions
                FOR SELECT TO %s
                USING (
                    current_setting('app.context_mode', true) = 'PROVIDER_CONTROL'
                    AND current_setting('app.provider_capability', true) = 'provider.approval.review'
                    AND app_provider_control_actor_allowed()
                    AND requester_provider_user_id <> app_provider_control_setting_uuid('app.provider_user_id')
                    AND operation_id = app_provider_control_setting_uuid('app.provider_operation_id')
                    AND EXISTS (
                        SELECT 1 FROM provider_control_operations o
                        WHERE o.id = provider_provision_revisions.operation_id
                          AND o.action_key = 'company.provision'
                          AND o.requester_provider_user_id = provider_provision_revisions.requester_provider_user_id
                    )
                )
            SQL, $control));

            DB::statement(sprintf(
                'GRANT SELECT (edit_reason_ciphertext), INSERT (edit_reason_ciphertext) ON provider_provision_revisions TO %s',
                $control,
            ));
        });
    }

    public function down(): void
    {
        throw new RuntimeException('Encrypted Provider revision reasons are immutable history; use a reviewed forward correction.');
    }

    private function runtimeRole(string $connection): string
    {
        $name = config("database.connections.{$connection}.username");
        if (! is_string($name) || ! preg_match('/^[a-z_][a-z0-9_]{0,62}$/D', $name)) {
            throw new RuntimeException("Missing or unsafe {$connection} runtime role.");
        }

        $role = DB::selectOne('SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname = ?', [$name]);
        $enabled = static fn (mixed $value): bool => in_array($value, [true, 't', 'true', '1', 1], true);
        if (! $role || ! $enabled($role->rolcanlogin) || $enabled($role->rolsuper)
            || $enabled($role->rolbypassrls) || $enabled($role->rolcreatedb) || $enabled($role->rolcreaterole)) {
            throw new RuntimeException("Unsafe {$connection} runtime role.");
        }

        return $name;
    }
};
