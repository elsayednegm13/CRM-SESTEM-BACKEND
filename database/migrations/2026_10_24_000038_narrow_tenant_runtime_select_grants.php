<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

/**
 * Narrows the tenant-staff runtime ACL back to what the services actually use
 * (DEV-FOUNDATION-01 / REMEDIATION-04, finding F09).
 *
 * Migration 037 had to grant whole-row SELECT on two tables because three existence checks
 * compiled to `EXISTS(SELECT *)`. Those checks now name a single granted column, and the three
 * always-NULL provenance columns are no longer listed in the service INSERTs, so both sets of
 * grants are dead. Only privileges that migration 037 added are revoked here: the migration
 * refuses to run if a revoke target belongs to the migration 026 contract, and it changes no
 * policy, trigger, role or ownership.
 */
return new class extends Migration
{
    /** Column SELECT grants established by migration 026; never revoked here. */
    private const CONTRACT_026 = [
        'tenant_staff_memberships' => ['id', 'tenant_id', 'staff_user_id', 'status', 'authorization_version'],
        'tenant_staff_membership_roles' => ['tenant_id', 'membership_id', 'role_id', 'revoked_at'],
    ];

    private const REVOKE_SELECT = [
        'tenant_staff_memberships' => ['joined_at', 'created_by_membership_id', 'created_by_provider_operation_id', 'created_at', 'updated_at'],
        'tenant_staff_membership_roles' => ['id', 'assigned_by_membership_id', 'assigned_by_provider_operation_id', 'assigned_at', 'revoked_by_membership_id', 'created_at', 'updated_at'],
    ];

    private const REVOKE_INSERT = [
        'tenant_staff_memberships' => ['created_by_provider_operation_id'],
        'tenant_staff_membership_roles' => ['assigned_by_provider_operation_id'],
        'tenant_staff_security_events' => ['provider_operation_id'],
    ];

    public function up(): void
    {
        $this->assertRuntimeGroupIsSafe();
        $this->assertWriteContractApplied();
        $this->assertDisjointFromContract026();

        foreach (self::REVOKE_SELECT as $table => $columns) {
            DB::statement('REVOKE SELECT ('.implode(', ', $columns).') ON public.'.$table.' FROM daleel_tenant_runtime');
        }
        foreach (self::REVOKE_INSERT as $table => $columns) {
            DB::statement('REVOKE INSERT ('.implode(', ', $columns).') ON public.'.$table.' FROM daleel_tenant_runtime');
        }

        $this->assertContract026Intact();
    }

    private function assertRuntimeGroupIsSafe(): void
    {
        DB::statement(<<<'SQL'
            DO $guard$
            DECLARE runtime pg_catalog.pg_roles%ROWTYPE;
            BEGIN
                SELECT * INTO runtime FROM pg_catalog.pg_roles WHERE rolname = 'daleel_tenant_runtime';
                IF NOT FOUND OR runtime.rolcanlogin OR runtime.rolsuper OR runtime.rolbypassrls
                   OR runtime.rolcreatedb OR runtime.rolcreaterole THEN
                    RAISE EXCEPTION 'daleel_tenant_runtime must exist as a NOLOGIN least-privilege group'
                        USING ERRCODE = '55000';
                END IF;
                IF pg_catalog.has_schema_privilege('daleel_tenant_runtime', 'public', 'CREATE')
                   OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                              WHERE n.nspname = 'public' AND c.relowner = runtime.oid) THEN
                    RAISE EXCEPTION 'daleel_tenant_runtime must not own objects or create in schema public'
                        USING ERRCODE = '55000';
                END IF;
            END
            $guard$
        SQL);
    }

    /** Only the grants added by migration 037 may be narrowed, so 037 must be recorded. */
    private function assertWriteContractApplied(): void
    {
        $applied = DB::table('migrations')
            ->where('migration', '2026_10_24_000037_grant_tenant_runtime_phase2_write_contract')
            ->exists();
        if (! $applied) {
            throw new RuntimeException('Migration 037 (tenant runtime write contract) must be applied first.');
        }
    }

    private function assertDisjointFromContract026(): void
    {
        foreach (self::REVOKE_SELECT as $table => $columns) {
            $overlap = array_intersect($columns, self::CONTRACT_026[$table] ?? []);
            if ($overlap !== []) {
                throw new RuntimeException('Refusing to revoke migration 026 columns on '.$table.': '.implode(', ', $overlap));
            }
        }
        foreach (array_merge_recursive(self::REVOKE_SELECT, self::REVOKE_INSERT) as $table => $columns) {
            foreach (array_unique($columns) as $column) {
                $granted = DB::selectOne('SELECT has_column_privilege(?, ?, ?, ?) AS allowed', [
                    'daleel_tenant_runtime', 'public.'.$table, $column,
                    in_array($column, self::REVOKE_SELECT[$table] ?? [], true) ? 'SELECT' : 'INSERT',
                ]);
                if (($granted->allowed ?? false) !== true) {
                    throw new RuntimeException('Expected '.$table.'.'.$column.' to be granted before narrowing it.');
                }
            }
        }
    }

    private function assertContract026Intact(): void
    {
        foreach (self::CONTRACT_026 as $table => $columns) {
            foreach ($columns as $column) {
                $granted = DB::selectOne('SELECT has_column_privilege(?, ?, ?, ?) AS allowed',
                    ['daleel_tenant_runtime', 'public.'.$table, $column, 'SELECT']);
                if (($granted->allowed ?? false) !== true) {
                    throw new RuntimeException('Narrowing removed a migration 026 privilege: '.$table.'.'.$column);
                }
            }
        }
    }

    public function down(): void
    {
        throw new LogicException('Runtime ACL migrations are forward-only; re-grant through a separately reviewed forward migration.');
    }
};
