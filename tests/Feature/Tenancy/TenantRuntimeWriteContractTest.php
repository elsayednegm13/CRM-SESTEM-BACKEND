<?php

namespace Tests\Feature\Tenancy;

use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Identity\Application\TenantStaffAccountService;
use App\Modules\Identity\Application\TenantStaffContextGuard;
use App\Modules\Identity\Application\TenantStaffRoleMutationService;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Application\LeadService;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use PDO;
use PDOException;
use RuntimeException;
use Tests\TestCase;

/**
 * Non-owner proof of the tenant-runtime write contract (migration 037, F05) on the locked RM02
 * target. Every write runs inside a transaction that is rolled back; fixtures are never changed.
 */
final class TenantRuntimeWriteContractTest extends TestCase
{
    private const TARGET_DATABASE = 'daleel_crm_rm02_isolated';
    private const TARGET_PORT = 55437;
    private const TARGET_SYSTEM_IDENTIFIER = '7699972247235194919';
    private const BASE_DOMAIN = 'acceptance.localhost';

    private array $tenant = [];
    private array $admin = [];
    private array $reader = [];
    private array $suspended = [];
    private array $op = [];
    private array $host = [];

    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('RLS_TEST_RUNTIME_USER') || ! getenv('RLS_TEST_RUNTIME_PASSWORD')) {
            $this->markTestSkipped('Non-owner tenant runtime role is not configured.');
        }
        $identity = DB::selectOne("SELECT current_database() AS name,
            (SELECT oid::text FROM pg_catalog.pg_database WHERE datname = current_database()) AS oid,
            (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_id,
            inet_server_port() AS server_port,
            (SELECT count(*) FROM migrations WHERE migration = '2026_10_24_000037_grant_tenant_runtime_phase2_write_contract') AS contract");
        $lockedOid = getenv('ACCEPTANCE_RM02_DB_OID');
        if ($identity->name !== self::TARGET_DATABASE
            || (int) config('database.connections.pgsql.port') !== self::TARGET_PORT
            || $identity->system_id !== self::TARGET_SYSTEM_IDENTIFIER
            || (int) $identity->server_port !== 5432
            || ! is_string($lockedOid) || $lockedOid === '' || $lockedOid !== $identity->oid
            || (int) $identity->contract !== 1) {
            throw new RuntimeException('Refusing write-contract proof outside the locked RM02 target with migration 037.');
        }
        foreach (['a', 'b'] as $letter) {
            $tenantId = DB::table('tenants')->where('slug', "rm02-{$letter}")->where('status', 'ACTIVE')->value('id');
            if (! is_string($tenantId)) {
                throw new RuntimeException('RM02 fixtures are missing.');
            }
            $this->tenant[$letter] = $tenantId;
            $this->admin[$letter] = $this->staff($tenantId, "rm02-admin-{$letter}@proof.invalid");
            $this->op[$letter] = DB::table('provider_control_operations')->where('target_tenant_id', $tenantId)->value('id');
        }
        $this->reader = $this->staff($this->tenant['a'], 'rm02-reader-a@proof.invalid');
        $this->suspended = $this->staff($this->tenant['a'], 'rm02-suspended-a@proof.invalid');
    }

    protected function tearDown(): void
    {
        if (array_key_exists('pgsql_tenant_runtime', DB::getConnections())) {
            $runtime = DB::connection('pgsql_tenant_runtime');
            while ($runtime->transactionLevel() > 0) {
                $runtime->rollBack();
            }
        }
        parent::tearDown();
    }

    private function staff(string $tenantId, string $email): array
    {
        $row = DB::table('tenant_staff_users as u')
            ->join('tenant_staff_memberships as m', 'm.staff_user_id', '=', 'u.id')
            ->where('u.tenant_id', $tenantId)->where('u.canonical_email', $email)
            ->first(['u.id as user', 'm.id as membership', 'u.auth_version', 'm.authorization_version']);
        if (! $row) {
            throw new RuntimeException('RM02 staff fixture is missing.');
        }

        return ['user' => $row->user, 'membership' => $row->membership,
            'auth_version' => (int) $row->auth_version, 'authorization_version' => (int) $row->authorization_version];
    }

    private function runtimePdo(): PDO
    {
        $cfg = config('database.connections.pgsql');

        return new PDO("pgsql:host={$cfg['host']};port={$cfg['port']};dbname={$cfg['database']}",
            getenv('RLS_TEST_RUNTIME_USER'), getenv('RLS_TEST_RUNTIME_PASSWORD'),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]);
    }

    private function rows(PDO $pdo, string $sql, array $values = []): array
    {
        $query = $pdo->prepare($sql);
        $query->execute($values);

        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    private function affected(PDO $pdo, string $sql, array $values = []): int
    {
        $query = $pdo->prepare($sql);
        $query->execute($values);

        return $query->rowCount();
    }

    private function local(PDO $pdo, string $userId, string $tenantId, string $mode = 'TENANT'): void
    {
        foreach (['app.user_id' => $userId, 'app.tenant_id' => $tenantId, 'app.context_mode' => $mode] as $key => $value) {
            $this->rows($pdo, 'SELECT set_config(?, ?, true)', [$key, $value]);
        }
    }

    /** Runs $sql inside a savepoint and asserts the SQLSTATE and message class of its failure. */
    private function assertFails(PDO $pdo, string $sql, array $values, string $sqlState, ?string $reason): void
    {
        $pdo->exec('SAVEPOINT rm03_check');
        try {
            $this->rows($pdo, $sql, $values);
            $this->fail("Statement was not rejected: {$sql}");
        } catch (PDOException $exception) {
            $this->assertSame($sqlState, $exception->getCode(), $sql);
            if ($reason !== null) {
                $this->assertStringContainsString($reason, $exception->getMessage(), $sql);
            }
        } finally {
            $pdo->exec('ROLLBACK TO SAVEPOINT rm03_check');
        }
    }

    private function objectDenied(PDO $pdo, string $sql, array $values = []): void
    {
        $this->assertFails($pdo, $sql, $values, '42501', 'permission denied');
    }

    private function rlsDenied(PDO $pdo, string $sql, array $values = []): void
    {
        $this->assertFails($pdo, $sql, $values, '42501', 'row-level security');
    }

    private function hostFor(string $letter): TenantHostContext
    {
        return $this->host[$letter] ??= app(TenantHostResolver::class)->resolve("rm02-{$letter}.".self::BASE_DOMAIN);
    }

    private function actAs(string $letter, string $userId, string $membershipId, int $authVersion, int $authorizationVersion): TenantStaffContext
    {
        $host = $this->hostFor($letter);

        return app(TenantStaffContextGuard::class)->activateFromSession($host, [
            'tenant_id' => $host->tenantId, 'hostname' => $host->hostname, 'user_id' => $userId,
            'membership_id' => $membershipId, 'auth_version' => $authVersion, 'authorization_version' => $authorizationVersion,
        ]);
    }

    private function actAsAdmin(string $letter): TenantStaffContext
    {
        $admin = $this->admin[$letter];

        return $this->actAs($letter, $admin['user'], $admin['membership'], $admin['auth_version'], $admin['authorization_version']);
    }

    /** Reader's live authorization_version inside the open runtime transaction (read under the admin A context). */
    private function actAsReader(Connection $runtime): TenantStaffContext
    {
        $this->actAsAdmin('a');
        $version = (int) $runtime->table('tenant_staff_memberships')->where('id', $this->reader['membership'])->value('authorization_version');

        return $this->actAs('a', $this->reader['user'], $this->reader['membership'], $this->reader['auth_version'], $version);
    }

    private function auditInserts(Connection $runtime): int
    {
        return (int) $runtime->selectOne("SELECT coalesce(sum(n_tup_ins), 0) AS n FROM pg_stat_xact_user_tables
            WHERE relname = 'tenant_staff_security_events'")->n;
    }

    private function denied(callable $operation): void
    {
        try {
            $operation();
            $this->fail('Unauthorized service operation succeeded.');
        } catch (AuthorizationDeniedException) {
            $this->assertTrue(true);
        }
    }

    public function test_effective_runtime_acl_matches_write_contract_for_both_runtime_logins(): void
    {
        $pdo = $this->runtimePdo();
        foreach ([getenv('RLS_TEST_RUNTIME_USER'), 'dl_truntime'] as $login) {
            $p = $this->rows($pdo, "SELECT
                has_column_privilege(x.r, 'roles', 'tenant_id', 'INSERT') AS roles_insert,
                has_column_privilege(x.r, 'roles', 'version', 'SELECT') AS roles_version_select,
                has_column_privilege(x.r, 'roles', 'status', 'UPDATE') AS roles_status_update,
                has_column_privilege(x.r, 'roles', 'tenant_id', 'UPDATE') AS roles_tenant_update,
                has_column_privilege(x.r, 'roles', 'display_name', 'UPDATE') AS roles_name_update,
                has_table_privilege(x.r, 'roles', 'DELETE') AS roles_delete,
                has_table_privilege(x.r, 'role_permissions', 'DELETE') AS role_permissions_delete,
                has_column_privilege(x.r, 'tenant_staff_users', 'password_hash', 'INSERT') AS hash_insert,
                has_column_privilege(x.r, 'tenant_staff_users', 'password_hash', 'SELECT') AS hash_select,
                has_any_column_privilege(x.r, 'tenant_staff_users', 'UPDATE') AS staff_update,
                has_table_privilege(x.r, 'tenant_staff_users', 'DELETE') AS staff_delete,
                has_column_privilege(x.r, 'tenant_staff_memberships', 'tenant_id', 'UPDATE') AS membership_tenant_update,
                has_column_privilege(x.r, 'tenant_staff_security_events', 'event_type', 'INSERT') AS audit_insert,
                has_any_column_privilege(x.r, 'tenant_staff_security_events', 'SELECT') AS audit_select,
                has_any_column_privilege(x.r, 'tenant_staff_security_events', 'UPDATE') AS audit_update,
                has_table_privilege(x.r, 'tenant_staff_security_events', 'DELETE') AS audit_delete,
                has_column_privilege(x.r, 'leads', 'name', 'SELECT') AS leads_select,
                has_column_privilege(x.r, 'leads', 'tenant_id', 'UPDATE') AS leads_tenant_update,
                has_column_privilege(x.r, 'leads', 'created_by_membership_id', 'UPDATE') AS leads_creator_update,
                has_table_privilege(x.r, 'leads', 'DELETE') AS leads_delete,
                has_any_column_privilege(x.r, 'tenants', 'UPDATE') AS tenants_update,
                has_any_column_privilege(x.r, 'users', 'SELECT') AS users_select,
                has_any_column_privilege(x.r, 'provider_control_operations', 'SELECT') AS provider_ops_select FROM (SELECT ?::name AS r) x",
                [$login])[0];
            foreach (['roles_insert', 'roles_version_select', 'roles_status_update', 'role_permissions_delete', 'hash_insert', 'audit_insert', 'leads_select'] as $allowed) {
                $this->assertTrue($p[$allowed], "{$login}:{$allowed}");
            }
            foreach (['roles_tenant_update', 'roles_name_update', 'roles_delete', 'hash_select', 'staff_update', 'staff_delete',
                'membership_tenant_update', 'audit_select', 'audit_update', 'audit_delete', 'leads_tenant_update',
                'leads_creator_update', 'leads_delete', 'tenants_update', 'users_select', 'provider_ops_select'] as $forbidden) {
                $this->assertFalse($p[$forbidden], "{$login}:{$forbidden}");
            }
        }

        // Migration 038 narrowing: the metadata columns 037 had to grant are gone again.
        if (! DB::table('migrations')->where('migration', '2026_10_24_000038_narrow_tenant_runtime_select_grants')->exists()) {
            $this->markTestIncomplete('Migration 038 is not applied on this target.');
        }
        foreach ([
            ['tenant_staff_memberships', 'joined_at', 'SELECT'],
            ['tenant_staff_memberships', 'created_by_membership_id', 'SELECT'],
            ['tenant_staff_memberships', 'created_by_provider_operation_id', 'SELECT'],
            ['tenant_staff_memberships', 'created_by_provider_operation_id', 'INSERT'],
            ['tenant_staff_membership_roles', 'id', 'SELECT'],
            ['tenant_staff_membership_roles', 'assigned_at', 'SELECT'],
            ['tenant_staff_membership_roles', 'assigned_by_provider_operation_id', 'INSERT'],
            ['tenant_staff_security_events', 'provider_operation_id', 'INSERT'],
        ] as [$table, $column, $privilege]) {
            $this->assertFalse($this->rows($pdo, 'SELECT has_column_privilege(?, ?, ?, ?) AS allowed',
                [getenv('RLS_TEST_RUNTIME_USER'), $table, $column, $privilege])[0]['allowed'],
                "{$table}.{$column} must no longer be {$privilege}-able");
        }
        // The migration 026 contract is untouched by the narrowing.
        foreach ([['tenant_staff_memberships', 'authorization_version'], ['tenant_staff_membership_roles', 'role_id'],
            ['tenant_staff_membership_roles', 'revoked_at'], ['tenant_staff_memberships', 'staff_user_id']] as [$table, $column]) {
            $this->assertTrue($this->rows($pdo, 'SELECT has_column_privilege(?, ?, ?, ?) AS allowed',
                [getenv('RLS_TEST_RUNTIME_USER'), $table, $column, 'SELECT'])[0]['allowed'], "{$table}.{$column} must stay readable");
        }
        $pdo->beginTransaction();
        try {
            $this->objectDenied($pdo, 'SELECT joined_at FROM tenant_staff_memberships');
            $this->objectDenied($pdo, 'SELECT id FROM tenant_staff_membership_roles');
            // Narrowing tsmr.id also blocks filtering that table by its surrogate key, which the
            // services never do: they revoke by (tenant_id, membership_id, role_id).
            $this->objectDenied($pdo, 'UPDATE tenant_staff_membership_roles SET revoked_at = now() WHERE id = ?', [(string) Str::uuid()]);
        } finally {
            $pdo->rollBack();
        }
    }

    public function test_raw_own_tenant_writes_succeed_and_cross_tenant_writes_are_rls_confined(): void
    {
        $pdo = $this->runtimePdo();
        $a = $this->tenant['a'];
        $b = $this->tenant['b'];
        $roleB = DB::table('roles')->where('tenant_id', $b)->value('id');
        $pdo->beginTransaction();
        try {
            $this->local($pdo, $this->admin['a']['user'], $a);
            $role = (string) Str::uuid();
            $this->assertSame(1, $this->affected($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)', [$role, $a, 'RM03 Raw', 'rm03_raw']));
            $this->rlsDenied($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)', [(string) Str::uuid(), $b, 'X', 'rm03_x']);
            $this->assertSame([['version' => 1]], $this->rows($pdo, "UPDATE roles SET status = 'ACTIVE' WHERE id = ? RETURNING version", [$role]));
            $this->objectDenied($pdo, "UPDATE roles SET status = 'ACTIVE' WHERE id = ? RETURNING created_at", [$role]);
            $this->assertSame(0, $this->affected($pdo, "UPDATE roles SET status = 'ARCHIVED' WHERE id = ?", [$roleB]));
            $this->objectDenied($pdo, 'UPDATE roles SET tenant_id = ? WHERE id = ?', [$b, $role]);

            $this->assertSame(1, $this->affected($pdo, "INSERT INTO role_permissions (tenant_id, role_id, permission_key, scope) VALUES (?, ?, 'role.view', NULL)", [$a, $role]));
            $this->rlsDenied($pdo, "INSERT INTO role_permissions (tenant_id, role_id, permission_key, scope) VALUES (?, ?, 'role.view', NULL)", [$b, $roleB]);
            $this->assertFails($pdo, "INSERT INTO role_permissions (tenant_id, role_id, permission_key, scope) VALUES (?, ?, 'role.view', NULL)", [$a, $roleB], '23503', null);
            $this->assertSame(0, $this->affected($pdo, 'DELETE FROM role_permissions WHERE role_id = ?', [$roleB]));
            $this->assertSame(1, $this->affected($pdo, 'DELETE FROM role_permissions WHERE role_id = ?', [$role]));

            $lead = (string) Str::uuid();
            $insertLead = 'INSERT INTO leads (id, tenant_id, name, created_by_membership_id, assigned_membership_id) VALUES (?, ?, ?, ?, ?)';
            $this->assertSame(1, $this->affected($pdo, $insertLead, [$lead, $a, 'RM03 raw lead', $this->admin['a']['membership'], null]));
            $this->rlsDenied($pdo, $insertLead, [(string) Str::uuid(), $b, 'X', $this->admin['b']['membership'], null]);
            $this->assertFails($pdo, $insertLead, [(string) Str::uuid(), $a, 'X', $this->admin['a']['membership'], $this->admin['b']['membership']], '23503', null);
            $this->assertSame(1, $this->affected($pdo, "UPDATE leads SET pipeline_stage = 'contacted' WHERE id = ?", [$lead]));
            $this->objectDenied($pdo, 'UPDATE leads SET tenant_id = ? WHERE id = ?', [$b, $lead]);
            $this->objectDenied($pdo, 'UPDATE leads SET created_by_membership_id = ? WHERE id = ?', [$this->reader['membership'], $lead]);
            $this->objectDenied($pdo, 'DELETE FROM leads WHERE id = ?', [$lead]);
            $this->assertSame([['id' => $lead]], $this->rows($pdo, 'SELECT id FROM leads'));

            $assignment = (string) Str::uuid();  // inserted below; never used as a filter
            $this->assertSame(1, $this->affected($pdo, 'INSERT INTO tenant_staff_membership_roles (id, tenant_id, membership_id, role_id, assigned_by_membership_id) VALUES (?, ?, ?, ?, ?)',
                [$assignment, $a, $this->reader['membership'], $role, $this->admin['a']['membership']]));
            $this->rlsDenied($pdo, 'INSERT INTO tenant_staff_membership_roles (id, tenant_id, membership_id, role_id, assigned_by_membership_id) VALUES (?, ?, ?, ?, ?)',
                [(string) Str::uuid(), $a, $this->suspended['membership'], $role, $this->reader['membership']]);
            $this->assertFails($pdo, 'INSERT INTO tenant_staff_membership_roles (id, tenant_id, membership_id, role_id, assigned_by_provider_operation_id) VALUES (?, ?, ?, ?, ?)',
                [(string) Str::uuid(), $a, $this->suspended['membership'], $role, $this->op['a']], '42501', null);
            // Revoke by the key shape the service uses; tsmr.id is deliberately unreadable after 038.
            $this->assertSame(1, $this->affected($pdo, 'UPDATE tenant_staff_membership_roles SET revoked_at = now(), revoked_by_membership_id = ?
                WHERE tenant_id = ? AND membership_id = ? AND role_id = ? AND revoked_at IS NULL',
                [$this->admin['a']['membership'], $a, $this->reader['membership'], $role]));

            $this->assertSame(1, $this->affected($pdo, "INSERT INTO tenant_staff_permission_grants (id, tenant_id, membership_id, permission_key, granted_by_membership_id) VALUES (?, ?, ?, 'role.view', ?)",
                [(string) Str::uuid(), $a, $this->reader['membership'], $this->admin['a']['membership']]));
            $this->rlsDenied($pdo, "INSERT INTO tenant_staff_permission_grants (id, tenant_id, membership_id, permission_key, granted_by_membership_id) VALUES (?, ?, ?, 'role.view', ?)",
                [(string) Str::uuid(), $b, $this->admin['b']['membership'], $this->admin['b']['membership']]);
            $this->assertSame(0, $this->affected($pdo, "UPDATE tenant_staff_permission_grants SET revoked_at = now(), revoked_by_membership_id = ? WHERE tenant_id = ?", [$this->admin['a']['membership'], $b]));

            $this->assertSame(1, $this->affected($pdo, 'UPDATE tenant_staff_memberships SET authorization_version = authorization_version + 1 WHERE id = ?', [$this->reader['membership']]));
            $this->assertSame(0, $this->affected($pdo, "UPDATE tenant_staff_memberships SET status = 'SUSPENDED' WHERE id = ?", [$this->admin['b']['membership']]));

            $staff = (string) Str::uuid();
            $this->assertSame(1, $this->affected($pdo, "INSERT INTO tenant_staff_users (id, tenant_id, canonical_email, display_email, display_name, password_hash) VALUES (?, ?, 'rm03-raw@proof.invalid', 'rm03-raw@proof.invalid', 'RM03 Raw', '\$argon2id\$rm03-synthetic')", [$staff, $a]));
            $this->assertSame(1, $this->affected($pdo, 'INSERT INTO tenant_staff_memberships (id, tenant_id, staff_user_id, created_by_membership_id) VALUES (?, ?, ?, ?)', [(string) Str::uuid(), $a, $staff, $this->admin['a']['membership']]));
            $this->objectDenied($pdo, 'SELECT password_hash FROM tenant_staff_users WHERE id = ?', [$staff]);
            $this->rlsDenied($pdo, "INSERT INTO tenant_staff_users (id, tenant_id, canonical_email, display_email, display_name, password_hash) VALUES (?, ?, 'rm03-x@proof.invalid', 'rm03-x@proof.invalid', 'X', '\$argon2id\$rm03-synthetic')", [(string) Str::uuid(), $b]);

            // After migration 038 the audit insert may no longer name provider_operation_id at all.
            $audit = "INSERT INTO tenant_staff_security_events (id, tenant_id, event_type, outcome, actor_membership_id, target_role_id) VALUES (?, ?, 'tenant_staff.role_created', 'SUCCESS', ?, ?)";
            $auditId = (string) Str::uuid();
            $this->assertSame(1, $this->affected($pdo, $audit, [$auditId, $a, $this->admin['a']['membership'], $role]));
            $this->rlsDenied($pdo, $audit, [(string) Str::uuid(), $a, $this->reader['membership'], $role]);
            $this->rlsDenied($pdo, $audit, [(string) Str::uuid(), $b, $this->admin['a']['membership'], $roleB]);
            // Claiming provider provenance is now blocked by the ACL before RLS is consulted.
            $this->objectDenied($pdo, "INSERT INTO tenant_staff_security_events (id, tenant_id, event_type, outcome, provider_operation_id, target_role_id) VALUES (?, ?, 'tenant_staff.role_created', 'SUCCESS', ?, ?)",
                [(string) Str::uuid(), $a, $this->op['a'], $role]);
            $this->objectDenied($pdo, 'SELECT id FROM tenant_staff_security_events');
            $this->objectDenied($pdo, "UPDATE tenant_staff_security_events SET outcome = 'FAILED' WHERE id = ?", [$auditId]);
            $this->objectDenied($pdo, 'DELETE FROM tenant_staff_security_events WHERE id = ?', [$auditId]);

            $this->local($pdo, $this->suspended['user'], $a);
            $this->rlsDenied($pdo, $audit, [(string) Str::uuid(), $a, $this->suspended['membership'], $role]);
            $this->rlsDenied($pdo, 'INSERT INTO tenant_staff_membership_roles (id, tenant_id, membership_id, role_id, assigned_by_membership_id) VALUES (?, ?, ?, ?, ?)',
                [(string) Str::uuid(), $a, $this->reader['membership'], $role, $this->suspended['membership']]);

            $this->local($pdo, '', '', '');
            $this->rlsDenied($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)', [(string) Str::uuid(), $a, 'X', 'rm03_none']);
            $this->rlsDenied($pdo, $insertLead, [(string) Str::uuid(), $a, 'X', $this->admin['a']['membership'], null]);
            $this->assertSame(0, $this->affected($pdo, "UPDATE leads SET name = 'none' WHERE id = ?", [$lead]));
            $this->assertSame(0, $this->affected($pdo, 'DELETE FROM role_permissions'));
        } finally {
            $pdo->rollBack();
        }
        $this->assertSame(0, DB::table('leads')->count());
        $this->assertSame(0, DB::table('tenant_staff_security_events')->count());
        $this->assertSame(3, DB::table('roles')->count());
    }

    public function test_trigger_guarded_inserts_are_stable_across_repeated_executions(): void
    {
        $pdo = $this->runtimePdo();
        $a = $this->tenant['a'];
        $pdo->beginTransaction();
        try {
            $this->local($pdo, $this->admin['a']['user'], $a);
            for ($i = 0; $i < 30; $i++) {
                $role = (string) Str::uuid();
                $this->affected($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)', [$role, $a, "RM03 Loop {$i}", "rm03_loop_{$i}"]);
                $this->assertSame(1, $this->affected($pdo, 'INSERT INTO tenant_staff_membership_roles (id, tenant_id, membership_id, role_id, assigned_by_membership_id) VALUES (?, ?, ?, ?, ?)',
                    [(string) Str::uuid(), $a, $this->reader['membership'], $role, $this->admin['a']['membership']]), "assignment {$i}");
                $staff = (string) Str::uuid();
                $this->affected($pdo, "INSERT INTO tenant_staff_users (id, tenant_id, canonical_email, display_email, display_name, password_hash) VALUES (?, ?, ?, ?, 'RM03 Loop', '\$argon2id\$rm03-synthetic')",
                    [$staff, $a, "rm03-loop-{$i}@proof.invalid", "rm03-loop-{$i}@proof.invalid"]);
                $this->assertSame(1, $this->affected($pdo, 'INSERT INTO tenant_staff_memberships (id, tenant_id, staff_user_id, created_by_membership_id) VALUES (?, ?, ?, ?)',
                    [(string) Str::uuid(), $a, $staff, $this->admin['a']['membership']]), "membership {$i}");
            }
        } finally {
            $pdo->rollBack();
        }
        $this->assertSame(4, DB::table('tenant_staff_memberships')->count());
    }

    public function test_laravel_role_membership_and_audit_services_under_runtime_principal(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $this->assertSame(getenv('RLS_TEST_RUNTIME_USER'), $runtime->selectOne('SELECT current_user AS name')->name);
        $roles = app(TenantStaffRoleMutationService::class);
        $accounts = app(TenantStaffAccountService::class);
        $runtime->beginTransaction();
        try {
            $admin = $this->actAsAdmin('a');
            $audit = $this->auditInserts($runtime);
            $sales = $roles->createRole($admin, 'RM03 Sales');
            $roles->updateRoleGrants($admin, $sales, [['permission' => 'leads.view', 'scope' => 'ASSIGNED'], ['permission' => 'leads.manage', 'scope' => 'ASSIGNED']]);
            $this->assertSame(2, $runtime->table('role_permissions')->where('role_id', $sales)->count());
            $temp = $roles->createRole($admin, 'RM03 Temp');
            $roles->archiveRole($admin, $temp);
            $this->assertSame('ARCHIVED', $runtime->table('roles')->where('id', $temp)->value('status'));
            $roles->assignRole($admin, $this->reader['membership'], $sales);
            $roles->grantPermission($admin, $this->reader['membership'], 'role.view', null);
            $roles->revokePermission($admin, $this->reader['membership'], 'role.view', null);
            $accounts->disableStaffMember($admin, $this->reader['membership']);
            $this->assertSame('SUSPENDED', $runtime->table('tenant_staff_memberships')->where('id', $this->reader['membership'])->value('status'));
            $accounts->reactivateStaffMember($admin, $this->reader['membership']);
            $this->assertSame(9, $this->auditInserts($runtime) - $audit, 'one audit event per successful operation');
            $this->assertSame($this->reader['authorization_version'] + 5,
                (int) $runtime->table('tenant_staff_memberships')->where('id', $this->reader['membership'])->value('authorization_version'));

            $audit = $this->auditInserts($runtime);
            $versionBefore = (int) $runtime->table('tenant_staff_memberships')->where('id', $this->reader['membership'])->value('authorization_version');
            $runtime->statement('SAVEPOINT rm03_duplicate');
            $this->denied(fn () => $roles->assignRole($admin, $this->reader['membership'], $sales));
            $runtime->statement('ROLLBACK TO SAVEPOINT rm03_duplicate');
            $this->assertSame($versionBefore, (int) $runtime->table('tenant_staff_memberships')->where('id', $this->reader['membership'])->value('authorization_version'));
            $adminRole = $runtime->table('roles')->where('tenant_id', $this->tenant['a'])->where('normalized_name', 'company_admin')->value('id');
            $this->denied(fn () => $roles->updateRoleGrants($admin, $adminRole, []));
            $this->denied(fn () => $accounts->disableStaffMember($admin, $this->admin['a']['membership']));
            $this->denied(fn () => $roles->assignRole($admin, $this->admin['b']['membership'], $sales));
            $this->denied(fn () => $roles->grantPermission($admin, $this->admin['b']['membership'], 'role.view', null));
            $this->denied(fn () => $accounts->disableStaffMember($admin, $this->admin['b']['membership']));

            $reader = $this->actAsReader($runtime);
            $this->denied(fn () => $roles->createRole($reader, 'RM03 Forbidden'));
            $this->denied(fn () => $roles->assignRole($reader, $this->suspended['membership'], $sales));
            $this->denied(fn () => $accounts->disableStaffMember($reader, $this->suspended['membership']));
            $this->assertSame(0, $this->auditInserts($runtime) - $audit, 'denied or failed operations write no audit event');
        } finally {
            $runtime->rollBack();
        }
        $this->assertSame(3, DB::table('roles')->count());
        $this->assertSame(0, DB::table('tenant_staff_security_events')->count());
        $this->assertSame($this->reader['authorization_version'], (int) DB::table('tenant_staff_memberships')->where('id', $this->reader['membership'])->value('authorization_version'));
    }

    public function test_laravel_lead_scopes_and_cross_tenant_isolation_under_runtime_principal(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $roles = app(TenantStaffRoleMutationService::class);
        $leads = app(LeadService::class);
        $runtime->beginTransaction();
        try {
            $admin = $this->actAsAdmin('a');
            $unassigned = $leads->createLead($admin, ['name' => 'RM03 Unassigned'])['id'];
            $assigned = $leads->createLead($admin, ['name' => 'RM03 Assigned', 'assigned_membership_id' => $this->reader['membership']])['id'];
            $rep = $roles->createRole($admin, 'RM03 Lead Rep');
            $roles->updateRoleGrants($admin, $rep, [['permission' => 'leads.view', 'scope' => 'ASSIGNED'], ['permission' => 'leads.manage', 'scope' => 'ASSIGNED']]);
            $roles->assignRole($admin, $this->reader['membership'], $rep);

            $reader = $this->actAsReader($runtime);
            $this->assertSame([$assigned], array_column($leads->listLeads($reader), 'id'));
            $this->denied(fn () => $leads->getLead($reader, $unassigned));
            $this->denied(fn () => $leads->updateStage($reader, $unassigned, 'contacted'));
            $this->assertSame('contacted', $leads->updateStage($reader, $assigned, 'contacted')['pipeline_stage']);
            $this->denied(fn () => $leads->assignLead($reader, $assigned, $this->admin['a']['membership']));
            $own = $leads->createLead($reader, ['name' => 'RM03 Reader Own', 'assigned_membership_id' => $this->admin['a']['membership']]);
            $this->assertSame($this->reader['membership'], $own['assigned_membership_id'], 'non-ALL_TENANT creator is forced to self-assignment');
            $visible = array_column($leads->listLeads($reader), 'id');
            sort($visible);
            $expected = [$assigned, $own['id']];
            sort($expected);
            $this->assertSame($expected, $visible);

            $admin = $this->actAsAdmin('a');
            $roles->revokeRole($admin, $this->reader['membership'], $rep);
            $roles->grantPermission($admin, $this->reader['membership'], 'leads.view', 'SELF');
            $roles->grantPermission($admin, $this->reader['membership'], 'leads.manage', 'SELF');
            $this->assertSame('RM03 Unassigned', $leads->getLead($admin, $unassigned)['name']);

            $reader = $this->actAsReader($runtime);
            $this->assertSame([$own['id']], array_column($leads->listLeads($reader), 'id'), 'SELF sees only leads it created');
            $this->denied(fn () => $leads->getLead($reader, $assigned));
            $this->denied(fn () => $leads->archiveLead($reader, $assigned));

            $adminB = $this->actAsAdmin('b');
            $this->assertSame([], $leads->listLeads($adminB));
            $this->denied(fn () => $leads->getLead($adminB, $unassigned));
            $this->denied(fn () => $leads->updateLead($adminB, $unassigned, ['name' => 'Cross tenant']));
            $this->denied(fn () => $leads->archiveLead($adminB, $unassigned));
            $this->denied(fn () => $leads->assignLead($adminB, $unassigned, $this->admin['b']['membership']));

            $admin = $this->actAsAdmin('a');
            $this->assertSame('RM03 Unassigned', $leads->getLead($admin, $unassigned)['name']);
            $this->assertSame($this->reader['membership'], $leads->assignLead($admin, $unassigned, $this->reader['membership'])['assigned_membership_id']);
            $leads->archiveLead($admin, $unassigned);
            $this->assertNotContains($unassigned, array_column($leads->listLeads($admin), 'id'));
        } finally {
            $runtime->rollBack();
        }
        $this->assertSame(0, DB::table('leads')->count());
        $this->assertSame(3, DB::table('roles')->count());
    }

    /** F07 resolution: staff creation now works under least privilege, with no password_hash read. */
    public function test_f07_staff_creation_succeeds_under_runtime_principal_without_reading_password_hash(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $accounts = app(TenantStaffAccountService::class);
        $roles = app(TenantStaffRoleMutationService::class);
        $statements = [];
        DB::listen(static function ($query) use (&$statements): void {
            if ($query->connectionName === 'pgsql_tenant_runtime') {
                $statements[] = $query->sql;
            }
        });
        $runtime->beginTransaction();
        try {
            $admin = $this->actAsAdmin('a');
            $audit = $this->auditInserts($runtime);
            $created = $accounts->createStaffMember($admin, 'RM04-New@Proof.invalid', 'RM04 New Staff', 'rm04-synthetic-initial-pass');
            $this->assertTrue(Str::isUuid($created['membership_id']));
            $this->assertTrue(Str::isUuid($created['staff_user_id']));
            $this->assertSame(1, $this->auditInserts($runtime) - $audit, 'exactly one tenant_staff.created event');

            $row = $runtime->table('tenant_staff_users')->where('id', $created['staff_user_id'])
                ->first(['id', 'tenant_id', 'canonical_email', 'display_email', 'display_name', 'status', 'auth_version']);
            $this->assertSame($this->tenant['a'], $row->tenant_id, 'new staff belongs to tenant A');
            $this->assertSame('rm04-new@proof.invalid', $row->canonical_email, 'email is canonicalized');
            $this->assertSame('RM04-New@Proof.invalid', $row->display_email);
            $this->assertSame('ACTIVE', $row->status);
            $membership = $runtime->table('tenant_staff_memberships')->where('id', $created['membership_id'])
                ->first(['tenant_id', 'staff_user_id', 'status', 'authorization_version']);
            $this->assertSame($this->tenant['a'], $membership->tenant_id);
            $this->assertSame($created['staff_user_id'], $membership->staff_user_id);
            $this->assertSame('ACTIVE', $membership->status);
            $this->assertSame(1, (int) $membership->authorization_version);
            // The membership row satisfied tenant_staff_membership_creator_check
            // (num_nonnulls(created_by_membership_id, created_by_provider_operation_id) = 1) and the
            // creator trigger, so omitting the provider column left it NULL with the actor recorded.
            // The hash passed tenant_staff_password_argon2id_check, and stays unreadable here.
            $this->objectDenied($runtime->getPdo(), 'SELECT password_hash FROM tenant_staff_users WHERE id = ?', [$created['staff_user_id']]);

            // A role can be assigned to the new member straight away.
            $role = $roles->createRole($admin, 'RM04 New Role');
            $roles->assignRole($admin, $created['membership_id'], $role);
            $this->assertSame(1, $runtime->table('tenant_staff_membership_roles')
                ->where('membership_id', $created['membership_id'])->whereNull('revoked_at')->count());

            // Duplicate email is a validation failure, and it leaves nothing behind.
            $audit = $this->auditInserts($runtime);
            $before = [$runtime->table('tenant_staff_users')->count(), $runtime->table('tenant_staff_memberships')->count()];
            $runtime->statement('SAVEPOINT rm04_duplicate');
            try {
                $accounts->createStaffMember($admin, 'rm04-new@proof.invalid', 'RM04 Duplicate', 'rm04-synthetic-initial-pass');
                $this->fail('Duplicate staff email was accepted.');
            } catch (ValidationException $exception) {
                $this->assertArrayHasKey('email', $exception->errors());
            }
            $runtime->statement('ROLLBACK TO SAVEPOINT rm04_duplicate');
            $this->assertSame($before, [$runtime->table('tenant_staff_users')->count(), $runtime->table('tenant_staff_memberships')->count()]);
            $this->assertSame(0, $this->auditInserts($runtime) - $audit, 'a rejected creation writes no audit event');

            // Tenant B cannot see or touch the staff member created in tenant A.
            $adminB = $this->actAsAdmin('b');
            $this->assertSame(0, $runtime->table('tenant_staff_users')->where('id', $created['staff_user_id'])->count());
            $this->denied(fn () => $accounts->disableStaffMember($adminB, $created['membership_id']));
            $this->assertNotContains($created['membership_id'], array_column($accounts->listStaff($adminB), 'membership_id'));

            // A reader without member.manage may not create staff at all.
            $reader = $this->actAsReader($runtime);
            $this->denied(fn () => $accounts->createStaffMember($reader, 'rm04-forbidden@proof.invalid', 'RM04 Forbidden', 'rm04-synthetic-initial-pass'));
        } finally {
            $runtime->rollBack();
        }
        $this->assertSame(4, DB::table('tenant_staff_users')->count());
        $this->assertSame(4, DB::table('tenant_staff_memberships')->count());
        $this->assertSame(0, DB::table('tenant_staff_security_events')->count());
        $this->assertNotSame([], $statements);
        $this->assertStringContainsString('select exists(select "id" from "tenant_staff_users"', implode("\n", $statements),
            'the existence check must not compile to SELECT *');
    }

    /**
     * F09 proof: no statement issued by the Phase 2 services over the runtime connection reads the
     * metadata columns that migration 037 only granted to satisfy EXISTS(SELECT *).
     */
    public function test_f09_no_runtime_statement_reads_the_candidate_metadata_columns(): void
    {
        $candidates = [
            'tenant_staff_memberships' => ['joined_at', 'created_by_membership_id', 'created_by_provider_operation_id'],
            'tenant_staff_membership_roles' => ['assigned_by_membership_id', 'assigned_by_provider_operation_id', 'assigned_at', 'revoked_by_membership_id'],
        ];
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $reads = [];
        DB::listen(static function ($query) use (&$reads): void {
            if ($query->connectionName === 'pgsql_tenant_runtime' && stripos(ltrim($query->sql), 'select') === 0) {
                $reads[] = $query->sql;
            }
        });
        $accounts = app(TenantStaffAccountService::class);
        $roles = app(TenantStaffRoleMutationService::class);
        $leads = app(LeadService::class);
        $runtime->beginTransaction();
        try {
            $admin = $this->actAsAdmin('a');
            $accounts->listStaff($admin);
            $created = $accounts->createStaffMember($admin, 'rm04-audit@proof.invalid', 'RM04 Audit', 'rm04-synthetic-initial-pass');
            $role = $roles->createRole($admin, 'RM04 Audit Role');
            $roles->updateRoleGrants($admin, $role, [['permission' => 'leads.view', 'scope' => 'ASSIGNED']]);
            $roles->assignRole($admin, $created['membership_id'], $role);
            $roles->revokeRole($admin, $created['membership_id'], $role);
            $roles->grantPermission($admin, $created['membership_id'], 'member.view', null);
            $roles->revokePermission($admin, $created['membership_id'], 'member.view', null);
            $accounts->disableStaffMember($admin, $created['membership_id']);
            $accounts->reactivateStaffMember($admin, $created['membership_id']);
            $roles->archiveRole($admin, $role);
            $lead = $leads->createLead($admin, ['name' => 'RM04 Audit Lead']);
            $leads->assignLead($admin, $lead['id'], $created['membership_id']);
            $leads->updateStage($admin, $lead['id'], 'contacted');
            $leads->listLeads($admin);
            $leads->archiveLead($admin, $lead['id']);
        } finally {
            $runtime->rollBack();
        }

        $this->assertGreaterThan(20, count($reads), 'the audited run must cover the service read paths');
        $joined = implode("\n", $reads);
        foreach ($candidates as $table => $columns) {
            foreach ($columns as $column) {
                $this->assertSame(0, preg_match('/\b'.preg_quote($column, '/').'\b/i', $joined),
                    "{$table}.{$column} must not be read by any runtime statement");
            }
        }
        // `leads` is the only table a runtime read may still fetch whole (LeadService uses get()/first(),
        // and migration 037 grants every leads column for exactly that reason).
        foreach (array_filter($reads, static fn (string $sql): bool => str_contains(strtolower($sql), 'select *')) as $starQuery) {
            $this->assertStringContainsString('from "leads"', strtolower($starQuery), 'only leads may be read with SELECT *');
        }
        $this->assertSame(0, DB::table('leads')->count());
        $this->assertSame(4, DB::table('tenant_staff_memberships')->count());
    }

    /**
     * Equivalence proof for dropping the explicitly-NULL provenance columns from the service
     * inserts. Uses the privileged fixture connection (which can read every column) purely to
     * observe the stored values; the runtime write paths themselves are proven elsewhere.
     */
    public function test_omitted_provenance_columns_are_equivalent_to_explicit_null(): void
    {
        $catalog = DB::select("SELECT table_name, column_name, is_nullable, column_default
            FROM information_schema.columns WHERE table_schema = 'public'
              AND (table_name, column_name) IN (('tenant_staff_memberships','created_by_provider_operation_id'),
                ('tenant_staff_membership_roles','assigned_by_provider_operation_id'),
                ('tenant_staff_security_events','provider_operation_id'))");
        $this->assertCount(3, $catalog);
        foreach ($catalog as $column) {
            $this->assertSame('YES', $column->is_nullable, $column->table_name.'.'.$column->column_name);
            $this->assertNull($column->column_default, $column->table_name.'.'.$column->column_name);
        }

        DB::beginTransaction();
        try {
            DB::selectOne('SELECT set_config(?, ?, true)', ['app.user_id', $this->admin['a']['user']]);
            $observed = [];
            foreach (['omitted', 'explicit-null'] as $variant) {
                $staff = (string) Str::uuid();
                $membership = (string) Str::uuid();
                $assignment = (string) Str::uuid();  // inserted below; never used as a filter
                $event = (string) Str::uuid();
                $role = DB::table('roles')->where('tenant_id', $this->tenant['a'])->where('normalized_name', 'rm02_viewer')->value('id');
                DB::table('tenant_staff_users')->insert(['id' => $staff, 'tenant_id' => $this->tenant['a'],
                    'canonical_email' => "rm04-{$variant}@proof.invalid", 'display_email' => "rm04-{$variant}@proof.invalid",
                    'display_name' => 'RM04 Provenance', 'password_hash' => '$argon2id$rm04-synthetic']);
                $membershipRow = ['id' => $membership, 'tenant_id' => $this->tenant['a'], 'staff_user_id' => $staff,
                    'created_by_membership_id' => $this->admin['a']['membership']];
                $assignmentRow = ['id' => $assignment, 'tenant_id' => $this->tenant['a'], 'membership_id' => $membership,
                    'role_id' => $role, 'assigned_by_membership_id' => $this->admin['a']['membership']];
                $eventRow = ['id' => $event, 'tenant_id' => $this->tenant['a'], 'event_type' => 'tenant_staff.created',
                    'outcome' => 'SUCCESS', 'actor_membership_id' => $this->admin['a']['membership'], 'target_staff_user_id' => $staff];
                if ($variant === 'explicit-null') {
                    $membershipRow['created_by_provider_operation_id'] = null;
                    $assignmentRow['assigned_by_provider_operation_id'] = null;
                    $eventRow['provider_operation_id'] = null;
                }
                DB::table('tenant_staff_memberships')->insert($membershipRow);
                DB::table('tenant_staff_membership_roles')->insert($assignmentRow);
                DB::table('tenant_staff_security_events')->insert($eventRow);
                $observed[$variant] = [
                    DB::table('tenant_staff_memberships')->where('id', $membership)->value('created_by_provider_operation_id'),
                    DB::table('tenant_staff_memberships')->where('id', $membership)->value('created_by_membership_id'),
                    DB::table('tenant_staff_membership_roles')->where('id', $assignment)->value('assigned_by_provider_operation_id'),
                    DB::table('tenant_staff_security_events')->where('id', $event)->value('provider_operation_id'),
                ];
            }
            $this->assertSame([null, $this->admin['a']['membership'], null, null], $observed['omitted']);
            $this->assertSame($observed['explicit-null'], $observed['omitted'], 'omitting the column stores exactly what explicit NULL stored');
        } finally {
            DB::rollBack();
        }
        $this->assertSame(4, DB::table('tenant_staff_users')->count());
        $this->assertSame(0, DB::table('tenant_staff_security_events')->count());
    }

    /** Characterizes open finding F10: a suspended same-tenant membership is still assignable. */
    public function test_known_finding_f10_suspended_membership_is_accepted_as_lead_assignee(): void
    {
        /** @var Connection $runtime */
        $runtime = DB::connection('pgsql_tenant_runtime');
        $leads = app(LeadService::class);
        $runtime->beginTransaction();
        try {
            $admin = $this->actAsAdmin('a');
            $this->assertSame('SUSPENDED', $runtime->table('tenant_staff_memberships')
                ->where('id', $this->suspended['membership'])->value('status'));
            // createLead trusts the composite FK only, so a suspended member passes.
            $created = $leads->createLead($admin, ['name' => 'RM04 F10', 'assigned_membership_id' => $this->suspended['membership']]);
            $this->assertSame($this->suspended['membership'], $created['assigned_membership_id'],
                'F10 still reproduces in createLead; keep it on the risk register');
            // assignLead does check ACTIVE, so the inconsistency is confined to creation.
            $this->expectException(ValidationException::class);
            $leads->assignLead($admin, $created['id'], $this->suspended['membership']);
        } finally {
            $runtime->rollBack();
        }
    }
}
