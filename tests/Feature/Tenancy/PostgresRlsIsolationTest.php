<?php

namespace Tests\Feature\Tenancy;

use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Identity\Application\TenantStaffAdminInvariant;
use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Application\TenantStaffContextGuard;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;
use PDO;
use PDOException;
use RuntimeException;
use Tests\TestCase;

/**
 * Non-owner RLS proof for the tenant-staff runtime ACL defined by migration 026.
 * Runs only on the locked REMEDIATION-02 target; its permanent synthetic fixtures are seeded
 * by tools/dev-db/acceptance/rm02-fixtures.sql and are never created or removed here.
 */
final class PostgresRlsIsolationTest extends TestCase
{
    private const TARGET_DATABASE = 'daleel_crm_rm02_isolated';
    private const TARGET_PORT = 55437;
    private const TARGET_SYSTEM_IDENTIFIER = '7699972247235194919';
    private const RUNTIME_ROLE = 'daleel_b10b_tenant_runtime';
    private const RUNTIME_GROUP = 'daleel_tenant_runtime';
    private const OWNER_ROLE = 'daleel_b10b_owner';
    private const BASE_DOMAIN = 'acceptance.localhost';

    private const RLS_TABLES = [
        'leads', 'membership_roles', 'outbox_messages', 'provider_provision_revisions', 'role_permissions', 'roles',
        'security_audit_events', 'tenant_hostnames', 'tenant_limit_overrides', 'tenant_memberships',
        'tenant_staff_membership_roles', 'tenant_staff_memberships', 'tenant_staff_password_reset_tokens',
        'tenant_staff_permission_grants', 'tenant_staff_security_events', 'tenant_staff_users', 'tenant_subscriptions', 'tenants',
    ];

    /** Tables readable by the runtime through column grants, with a granted column to count. */
    private const RUNTIME_READABLE = [
        'tenants' => 'id', 'tenant_staff_users' => 'id', 'tenant_staff_memberships' => 'id',
        'tenant_staff_membership_roles' => 'role_id', 'tenant_staff_permission_grants' => 'membership_id',
        'roles' => 'id', 'role_permissions' => 'role_id', 'leads' => 'id',
    ];

    /** No SELECT at all for the runtime (migrations 026 + 037); audit events are insert-only. */
    private const RUNTIME_UNGRANTED = [
        'users', 'tenant_memberships', 'membership_roles', 'security_audit_events',
        'tenant_staff_security_events', 'tenant_subscriptions', 'tenant_limit_overrides',
    ];

    /** @var array<string,string> */
    private array $tenant = [];

    /** @var array<string,array{user:string,membership:string,auth_version:int,authorization_version:int}> */
    private array $admin = [];

    private array $reader = [];
    private array $suspended = [];
    private ?string $viewerRoleId = null;

    protected function setUp(): void
    {
        parent::setUp();
        if (! getenv('RLS_TEST_RUNTIME_USER') || ! getenv('RLS_TEST_RUNTIME_PASSWORD')) {
            $this->markTestSkipped('Non-owner tenant runtime role is not configured.');
        }
        $identity = DB::selectOne("SELECT current_database() AS name,
            (SELECT oid::text FROM pg_catalog.pg_database WHERE datname = current_database()) AS oid,
            (SELECT system_identifier::text FROM pg_catalog.pg_control_system()) AS system_id,
            inet_server_port() AS server_port");
        $lockedOid = getenv('ACCEPTANCE_RM02_DB_OID');
        if ($identity->name !== self::TARGET_DATABASE
            || (int) config('database.connections.pgsql.port') !== self::TARGET_PORT
            || $identity->system_id !== self::TARGET_SYSTEM_IDENTIFIER
            || (int) $identity->server_port !== 5432
            || ! is_string($lockedOid) || $lockedOid === '' || $lockedOid !== $identity->oid) {
            throw new RuntimeException('Refusing RLS proof outside the locked RM02 isolated target.');
        }

        foreach (['a', 'b'] as $letter) {
            $tenantId = DB::table('tenants')->where('slug', "rm02-{$letter}")->where('status', 'ACTIVE')->value('id');
            if (! is_string($tenantId)) {
                throw new RuntimeException('RM02 fixtures are missing; run rm02-tool.php fixtures first.');
            }
            $this->tenant[$letter] = $tenantId;
            $this->admin[$letter] = $this->staff($tenantId, "rm02-admin-{$letter}@proof.invalid");
        }
        $this->reader = $this->staff($this->tenant['a'], 'rm02-reader-a@proof.invalid');
        $this->suspended = $this->staff($this->tenant['a'], 'rm02-suspended-a@proof.invalid');
        $this->viewerRoleId = DB::table('roles')->where('tenant_id', $this->tenant['a'])
            ->where('normalized_name', 'rm02_viewer')->value('id');
        if (! is_string($this->viewerRoleId)) {
            throw new RuntimeException('RM02 viewer role fixture is missing.');
        }
        $this->normalizeViewerGrant();
    }

    protected function tearDown(): void
    {
        if (array_key_exists('pgsql_tenant_runtime', DB::getConnections())) {
            $runtime = DB::connection('pgsql_tenant_runtime');
            while ($runtime->transactionLevel() > 0) {
                $runtime->rollBack();
            }
        }
        if ($this->viewerRoleId !== null) {
            $this->normalizeViewerGrant();
        }
        parent::tearDown();
    }

    /** The only mutable fixture row: the viewer role's role.view grant, net zero per test. */
    private function normalizeViewerGrant(): void
    {
        DB::connection('pgsql')->table('role_permissions')
            ->where('tenant_id', $this->tenant['a'])->where('role_id', $this->viewerRoleId)->delete();
    }

    private function staff(string $tenantId, string $email): array
    {
        $row = DB::table('tenant_staff_users as u')
            ->join('tenant_staff_memberships as m', function ($join): void {
                $join->on('m.tenant_id', '=', 'u.tenant_id')->on('m.staff_user_id', '=', 'u.id');
            })
            ->where('u.tenant_id', $tenantId)->where('u.canonical_email', $email)
            ->first(['u.id as user', 'm.id as membership', 'u.auth_version', 'm.authorization_version']);
        if (! $row) {
            throw new RuntimeException('RM02 staff fixture is missing.');
        }

        return ['user' => $row->user, 'membership' => $row->membership,
            'auth_version' => (int) $row->auth_version, 'authorization_version' => (int) $row->authorization_version];
    }

    private function runtime(): PDO
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

    private function visible(PDO $pdo, string $table): int
    {
        return $this->rows($pdo, 'SELECT count('.self::RUNTIME_READABLE[$table].") AS n FROM {$table}")[0]['n'];
    }

    /** @return list<string> */
    private function ids(PDO $pdo, string $sql, array $values = []): array
    {
        $ids = array_column($this->rows($pdo, $sql, $values), 'id');
        sort($ids);

        return $ids;
    }

    /** @return list<string> */
    private function fixtureIds(string $table, string $tenantId): array
    {
        $ids = DB::table($table)->where('tenant_id', $tenantId)->pluck('id')->all();
        sort($ids);

        return $ids;
    }

    private function fixtureCount(string $table, string $tenantId): int
    {
        return DB::table($table)->where($table === 'tenants' ? 'id' : 'tenant_id', $tenantId)->count();
    }

    private function local(PDO $pdo, string $userId, string $tenantId, string $mode = 'TENANT'): void
    {
        foreach (['app.user_id' => $userId, 'app.tenant_id' => $tenantId, 'app.context_mode' => $mode] as $key => $value) {
            $this->rows($pdo, 'SELECT set_config(?, ?, true)', [$key, $value]);
        }
    }

    /** Object-level denial (missing grant), distinct from RLS row filtering (zero rows). */
    private function assertObjectDenied(PDO $pdo, string $sql, array $values = []): void
    {
        $this->assertDeniedWith($pdo, $sql, $values, 'permission denied');
    }

    /** RLS WITH CHECK rejection of a granted statement (also SQLSTATE 42501, different message). */
    private function assertRlsDenied(PDO $pdo, string $sql, array $values = []): void
    {
        $this->assertDeniedWith($pdo, $sql, $values, 'row-level security');
    }

    private function assertDeniedWith(PDO $pdo, string $sql, array $values, string $reason): void
    {
        $inTransaction = $pdo->inTransaction();
        if ($inTransaction) {
            $pdo->exec('SAVEPOINT rm02_denied');
        }
        try {
            $this->rows($pdo, $sql, $values);
            $this->fail("Runtime statement was not denied: {$sql}");
        } catch (PDOException $exception) {
            $this->assertSame('42501', $exception->getCode(), $sql);
            $this->assertStringContainsString($reason, $exception->getMessage(), $sql);
        } finally {
            if ($inTransaction) {
                $pdo->exec('ROLLBACK TO SAVEPOINT rm02_denied');
            }
        }
    }

    private function affected(PDO $pdo, string $sql, array $values = []): int
    {
        $query = $pdo->prepare($sql);
        $query->execute($values);

        return $query->rowCount();
    }

    private function staffSession(TenantHostContext $host, array $member, int $authorizationDelta = 0): array
    {
        return ['tenant_id' => $host->tenantId, 'hostname' => $host->hostname, 'user_id' => $member['user'],
            'membership_id' => $member['membership'], 'auth_version' => $member['auth_version'],
            'authorization_version' => $member['authorization_version'] + $authorizationDelta];
    }

    public function test_exact_table_policy_inventory_and_runtime_role_flags(): void
    {
        $protected = DB::table('pg_class as c')->join('pg_namespace as n', 'n.oid', '=', 'c.relnamespace')
            ->where('n.nspname', 'public')->where('c.relrowsecurity', true)
            ->orderBy('c.relname')->pluck('c.relname')->all();
        $this->assertSame(self::RLS_TABLES, $protected);
        $this->assertSame(count(self::RLS_TABLES), DB::table('pg_class as c')->join('pg_namespace as n', 'n.oid', '=', 'c.relnamespace')
            ->where('n.nspname', 'public')->whereIn('c.relname', self::RLS_TABLES)->where('c.relforcerowsecurity', true)->count());
        $this->assertSame(94, DB::table('pg_policies')->where('schemaname', 'public')->whereIn('tablename', self::RLS_TABLES)->count());

        $pdo = $this->runtime();
        $role = $this->rows($pdo, 'SELECT current_user, session_user, current_database() AS db,
            rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user')[0];
        $this->assertSame(self::RUNTIME_ROLE, $role['current_user']);
        $this->assertSame($role['current_user'], $role['session_user']);
        $this->assertSame(self::TARGET_DATABASE, $role['db']);
        foreach (['rolsuper', 'rolbypassrls', 'rolcreaterole', 'rolcreatedb'] as $flag) {
            $this->assertFalse($role[$flag], $flag);
        }
        $this->assertSame([['name' => self::OWNER_ROLE]], $this->rows($pdo, "SELECT DISTINCT pg_get_userbyid(c.relowner) AS name
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relrowsecurity"));
        $this->assertSame(0, $this->rows($pdo, "SELECT count(*) AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)")[0]['n']);
        $this->assertFalse($this->rows($pdo, "SELECT has_schema_privilege(current_user, 'public', 'CREATE') AS allowed")[0]['allowed']);
        $this->assertSame([['rolname' => self::RUNTIME_GROUP]], $this->rows($pdo, 'SELECT g.rolname FROM pg_auth_members m
            JOIN pg_roles g ON g.oid = m.roleid WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user) ORDER BY g.rolname'));
    }

    public function test_no_context_and_invalid_context_deny_reads_and_writes(): void
    {
        $pdo = $this->runtime();
        foreach (array_keys(self::RUNTIME_READABLE) as $table) {
            $this->assertSame(0, $this->visible($pdo, $table), "no-context {$table}");
        }
        $roleB = $this->fixtureIds('roles', $this->tenant['b'])[0];
        $this->assertObjectDenied($pdo, 'UPDATE roles SET display_name = ? WHERE id = ?', ['forbidden', $roleB]);
        $this->assertObjectDenied($pdo, 'DELETE FROM roles WHERE id = ?', [$roleB]);
        $this->assertRlsDenied($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)',
            [(string) Str::uuid(), $this->tenant['b'], 'Forbidden', 'forbidden']);
        $this->assertSame(0, $this->affected($pdo, "UPDATE roles SET status = 'ARCHIVED' WHERE id = ?", [$roleB]));
        $this->assertSame(0, $this->affected($pdo, 'DELETE FROM role_permissions WHERE role_id = ?', [$roleB]));
        $this->assertSame(0, $this->affected($pdo, "UPDATE leads SET status = 'ARCHIVED'"));
        foreach (self::RUNTIME_UNGRANTED as $table) {
            $this->assertObjectDenied($pdo, "SELECT count(*) AS n FROM {$table}");
        }

        $pdo->beginTransaction();
        $this->local($pdo, 'invalid', 'invalid');
        foreach (array_keys(self::RUNTIME_READABLE) as $table) {
            $this->assertSame(0, $this->visible($pdo, $table), "invalid-context {$table}");
        }
        $this->local($pdo, $this->admin['a']['user'], $this->tenant['a'], 'PROVIDER');
        foreach (array_keys(self::RUNTIME_READABLE) as $table) {
            $this->assertSame(0, $this->visible($pdo, $table), "wrong-mode {$table}");
        }
        $pdo->rollBack();
    }

    public function test_tenant_runtime_cannot_mutate_global_identity_rows_directly(): void
    {
        $pdo = $this->runtime();
        $privileges = $this->rows($pdo, "SELECT
            has_table_privilege(current_user, 'users', 'SELECT') AS users_select,
            has_table_privilege(current_user, 'users', 'INSERT') AS users_insert,
            has_table_privilege(current_user, 'users', 'UPDATE') AS users_update,
            has_table_privilege(current_user, 'users', 'DELETE') AS users_delete,
            has_table_privilege(current_user, 'tenant_staff_users', 'INSERT') AS staff_insert,
            has_table_privilege(current_user, 'tenant_staff_users', 'UPDATE') AS staff_update,
            has_table_privilege(current_user, 'tenant_staff_users', 'DELETE') AS staff_delete,
            has_column_privilege(current_user, 'tenant_staff_users', 'password_hash', 'SELECT') AS staff_hash_select,
            has_column_privilege(current_user, 'tenant_staff_users', 'password_hash', 'UPDATE') AS staff_hash_update,
            has_column_privilege(current_user, 'tenant_staff_users', 'status', 'UPDATE') AS staff_status_update,
            has_column_privilege(current_user, 'tenant_staff_users', 'auth_version', 'UPDATE') AS staff_auth_version_update")[0];
        foreach ($privileges as $key => $allowed) {
            $this->assertFalse($allowed, $key);
        }

        $adminA = $this->admin['a']['user'];
        $pdo->beginTransaction();
        $this->local($pdo, $adminA, $this->tenant['a']);
        $this->assertSame($this->fixtureIds('tenant_staff_users', $this->tenant['a']), $this->ids($pdo, 'SELECT id FROM tenant_staff_users'));
        foreach ([
            ["UPDATE tenant_staff_users SET status = 'DISABLED' WHERE id = ?", [$adminA]],
            ['UPDATE tenant_staff_users SET auth_version = auth_version + 1 WHERE id = ?', [$adminA]],
            ['UPDATE tenant_staff_users SET password_hash = ? WHERE id = ?', ['$argon2id$rm02-forbidden', $adminA]],
            ['DELETE FROM tenant_staff_users WHERE id = ?', [$adminA]],
            ['UPDATE tenant_staff_users SET tenant_id = ? WHERE id = ?', [$this->tenant['b'], $adminA]],
            ['SELECT password_hash FROM tenant_staff_users WHERE id = ?', [$adminA]],
            ['SELECT * FROM tenant_staff_users WHERE id = ?', [$adminA]],
            ['UPDATE tenant_staff_memberships SET tenant_id = ? WHERE id = ?', [$this->tenant['b'], $this->admin['a']['membership']]],
            ['DELETE FROM tenant_staff_memberships WHERE id = ?', [$this->admin['a']['membership']]],
            ['SELECT id FROM users', []],
            ["UPDATE users SET status = 'DISABLED'", []],
            ['INSERT INTO users (id, email, password) VALUES (?, ?, ?)', [(string) Str::uuid(), 'forbidden@proof.invalid', 'proof-only']],
        ] as [$sql, $values]) {
            $this->assertObjectDenied($pdo, $sql, $values);
        }
        $pdo->rollBack();

        $after = DB::table('tenant_staff_users')->where('id', $adminA)->first(['status', 'auth_version']);
        $this->assertSame('ACTIVE', $after->status);
        $this->assertSame($this->admin['a']['auth_version'], (int) $after->auth_version);
    }

    public function test_discovery_mode_and_inactive_or_forged_actor_expose_no_staff_access(): void
    {
        $pdo = $this->runtime();
        $pdo->beginTransaction();
        $this->local($pdo, $this->reader['user'], '', 'TENANT_DISCOVERY');
        foreach (array_keys(self::RUNTIME_READABLE) as $table) {
            $this->assertSame(0, $this->visible($pdo, $table), "discovery {$table}");
        }
        $this->assertObjectDenied($pdo, 'SELECT id FROM tenant_memberships');

        $this->local($pdo, $this->reader['user'], $this->tenant['a']);
        $this->assertSame($this->fixtureCount('tenant_staff_membership_roles', $this->tenant['a']), $this->visible($pdo, 'tenant_staff_membership_roles'));
        $this->assertSame($this->fixtureCount('tenant_staff_permission_grants', $this->tenant['a']), $this->visible($pdo, 'tenant_staff_permission_grants'));
        $this->assertGreaterThan(0, $this->visible($pdo, 'tenant_staff_membership_roles'));

        foreach ([
            'suspended actor' => [$this->suspended['user'], $this->tenant['a']],
            'A actor forged onto B' => [$this->reader['user'], $this->tenant['b']],
            'B actor forged onto A' => [$this->admin['b']['user'], $this->tenant['a']],
        ] as $label => [$userId, $tenantId]) {
            $this->local($pdo, $userId, $tenantId);
            $this->assertSame(0, $this->visible($pdo, 'tenant_staff_membership_roles'), $label);
            $this->assertSame(0, $this->visible($pdo, 'tenant_staff_permission_grants'), $label);
        }
        $pdo->rollBack();
    }

    public function test_raw_a_b_select_isolation_and_write_denial(): void
    {
        $pdo = $this->runtime();
        $pdo->beginTransaction();
        foreach (['a' => 'b', 'b' => 'a'] as $own => $other) {
            $this->local($pdo, $this->admin[$own]['user'], $this->tenant[$own]);
            $this->assertSame([$this->tenant[$own]], $this->ids($pdo, 'SELECT id FROM tenants'));
            $this->assertSame($this->fixtureIds('roles', $this->tenant[$own]), $this->ids($pdo, 'SELECT id FROM roles'));
            $this->assertSame($this->fixtureIds('tenant_staff_users', $this->tenant[$own]), $this->ids($pdo, 'SELECT id FROM tenant_staff_users'));
            $this->assertSame($this->fixtureIds('tenant_staff_memberships', $this->tenant[$own]), $this->ids($pdo, 'SELECT id FROM tenant_staff_memberships'));
            foreach (['role_permissions', 'tenant_staff_membership_roles', 'tenant_staff_permission_grants'] as $table) {
                $expected = $this->fixtureCount($table, $this->tenant[$own]);
                $this->assertGreaterThan(0, $expected, $table);
                $this->assertSame($expected, $this->visible($pdo, $table), "{$own}:{$table}");
            }
            foreach (['roles', 'tenant_staff_users', 'tenant_staff_memberships'] as $table) {
                $this->assertSame([], $this->rows($pdo, "SELECT id FROM {$table} WHERE tenant_id = ?", [$this->tenant[$other]]), "{$own} sees {$other} {$table}");
            }
            $this->assertSame([], $this->rows($pdo, 'SELECT id FROM tenants WHERE id = ?', [$this->tenant[$other]]));

            foreach ([$own, $other] as $target) {
                $this->assertObjectDenied($pdo, 'UPDATE roles SET display_name = ? WHERE tenant_id = ?', ['Denied', $this->tenant[$target]]);
                $this->assertObjectDenied($pdo, 'UPDATE roles SET tenant_id = ? WHERE tenant_id = ?', [$this->tenant[$other], $this->tenant[$target]]);
                $this->assertObjectDenied($pdo, 'DELETE FROM roles WHERE tenant_id = ?', [$this->tenant[$target]]);
            }
            $pdo->exec('SAVEPOINT rm02_own_write');
            $this->assertSame(1, $this->affected($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)',
                [(string) Str::uuid(), $this->tenant[$own], 'Own write', 'own_write']));
            $this->assertSame($this->fixtureCount('role_permissions', $this->tenant[$own]),
                $this->affected($pdo, 'DELETE FROM role_permissions WHERE tenant_id = ?', [$this->tenant[$own]]));
            $pdo->exec('ROLLBACK TO SAVEPOINT rm02_own_write');
            $this->assertRlsDenied($pdo, 'INSERT INTO roles (id, tenant_id, display_name, normalized_name) VALUES (?, ?, ?, ?)',
                [(string) Str::uuid(), $this->tenant[$other], 'Denied', 'denied_write']);
            $this->assertSame(0, $this->affected($pdo, "UPDATE roles SET status = 'ARCHIVED' WHERE tenant_id = ?", [$this->tenant[$other]]));
            $this->assertSame(0, $this->affected($pdo, 'DELETE FROM role_permissions WHERE tenant_id = ?', [$this->tenant[$other]]));
            $this->assertSame([], $this->rows($pdo, 'SELECT id FROM leads WHERE tenant_id = ?', [$this->tenant[$other]]));
        }
        $pdo->rollBack();

        foreach (['a', 'b'] as $letter) {
            $this->assertSame(['Company Admin'], DB::table('roles')->where('tenant_id', $this->tenant[$letter])
                ->where('normalized_name', 'company_admin')->pluck('display_name')->all());
        }
    }

    public function test_same_backend_connection_a_b_none_and_rollback_exception_reset(): void
    {
        $pdo = $this->runtime();
        $pid = $this->rows($pdo, 'SELECT pg_backend_pid() AS pid')[0]['pid'];
        foreach (['a', 'b'] as $letter) {
            $pdo->beginTransaction();
            $this->local($pdo, $this->admin[$letter]['user'], $this->tenant[$letter]);
            $this->assertSame([['id' => $this->tenant[$letter]]], $this->rows($pdo, 'SELECT id FROM tenants'));
            $pdo->commit();
            $this->assertSame(0, $this->visible($pdo, 'tenants'));
            $this->assertSame($pid, $this->rows($pdo, 'SELECT pg_backend_pid() AS pid')[0]['pid']);
        }
        $pdo->beginTransaction();
        $this->local($pdo, $this->admin['a']['user'], $this->tenant['a']);
        $pdo->rollBack();
        $this->assertSame(0, $this->visible($pdo, 'roles'));
        try {
            $pdo->beginTransaction();
            $this->local($pdo, $this->admin['a']['user'], $this->tenant['a']);
            throw new RuntimeException('Proof exception');
        } catch (RuntimeException) {
            $pdo->rollBack();
        }
        $this->assertSame(0, $this->visible($pdo, 'tenants'));
    }

    public function test_two_simultaneously_open_runtime_transactions_keep_a_and_b_separate(): void
    {
        $a = $this->runtime();
        $b = $this->runtime();
        $a->beginTransaction();
        $b->beginTransaction();
        try {
            $this->local($a, $this->admin['a']['user'], $this->tenant['a']);
            $this->local($b, $this->admin['b']['user'], $this->tenant['b']);
            $pidA = $this->rows($a, 'SELECT pg_backend_pid() AS pid')[0]['pid'];
            $pidB = $this->rows($b, 'SELECT pg_backend_pid() AS pid')[0]['pid'];
            $this->assertNotSame($pidA, $pidB);
            $this->assertSame(2, DB::table('pg_stat_activity')->whereIn('pid', [$pidA, $pidB])
                ->where('state', 'idle in transaction')->count());
            $this->assertSame([['id' => $this->tenant['a']]], $this->rows($a, 'SELECT id FROM tenants'));
            $this->assertSame([['id' => $this->tenant['b']]], $this->rows($b, 'SELECT id FROM tenants'));
            $this->assertSame([], $this->rows($a, 'SELECT id FROM roles WHERE tenant_id = ?', [$this->tenant['b']]));
            $this->assertSame([], $this->rows($b, 'SELECT id FROM roles WHERE tenant_id = ?', [$this->tenant['a']]));
        } finally {
            $a->rollBack();
            $b->rollBack();
        }
    }

    public function test_real_laravel_host_resolver_staff_guard_and_rbac_freshness(): void
    {
        $runtime = DB::connection('pgsql_tenant_runtime');
        $this->assertSame(self::RUNTIME_ROLE, $runtime->selectOne('SELECT current_user AS name')->name);
        $this->assertSame('dl_host', DB::connection('pgsql_hostname_resolver')->selectOne('SELECT current_user AS name')->name);

        $resolver = app(TenantHostResolver::class);
        $hostA = $resolver->resolve('rm02-a.'.self::BASE_DOMAIN);
        $hostB = $resolver->resolve('rm02-b.'.self::BASE_DOMAIN);
        $this->assertSame($this->tenant['a'], $hostA->tenantId);
        $this->assertSame($this->tenant['b'], $hostB->tenantId);
        try {
            $resolver->resolve('rm02-unmapped.'.self::BASE_DOMAIN);
            $this->fail('An unmapped tenant host resolved.');
        } catch (InvalidArgumentException) {
            $this->assertTrue(true);
        }

        $guard = app(TenantStaffContextGuard::class);
        $auth = app(TenantStaffAuthorizationService::class);
        $runtime->beginTransaction();
        try {
            $context = $guard->activateFromSession($hostA, $this->staffSession($hostA, $this->reader));
            $this->assertSame($this->tenant['a'], $context->tenantId);
            try {
                $auth->listRoles($context);
                $this->fail('RBAC allowed role listing without role.view.');
            } catch (AuthorizationDeniedException) {
                $this->assertTrue(true);
            }

            DB::connection('pgsql')->table('role_permissions')->insert([
                'tenant_id' => $this->tenant['a'], 'role_id' => $this->viewerRoleId, 'permission_key' => 'role.view', 'scope' => null,
            ]);
            $listed = array_column($auth->listRoles($context), 'id');
            sort($listed);
            $expected = DB::table('roles')->where('tenant_id', $this->tenant['a'])->where('status', 'ACTIVE')
                ->whereNull('archived_at')->pluck('id')->all();
            sort($expected);
            $this->assertSame($expected, $listed);
            $this->assertSame([], array_values(array_intersect($listed, $this->fixtureIds('roles', $this->tenant['b']))));

            $this->normalizeViewerGrant();
            try {
                $auth->listRoles($context);
                $this->fail('Revoked role.view remained available.');
            } catch (AuthorizationDeniedException) {
                $this->assertTrue(true);
            }
        } finally {
            $runtime->rollBack();
        }

        foreach ([
            'suspended membership' => [$hostA, $this->staffSession($hostA, $this->suspended)],
            'A session presented on B host' => [$hostB, $this->staffSession($hostA, $this->reader)],
            'A identity forged into B session' => [$hostB, $this->staffSession($hostB, $this->reader)],
            'stale authorization version' => [$hostA, $this->staffSession($hostA, $this->reader, 1)],
        ] as $label => [$host, $stored]) {
            $runtime->beginTransaction();
            try {
                $guard->activateFromSession($host, $stored);
                $this->fail("Tenant staff guard accepted: {$label}");
            } catch (TenantAccessException) {
                $this->assertTrue(true);
            } finally {
                $runtime->rollBack();
            }
        }
    }

    public function test_savepoint_rollback_restores_context_and_last_admin_invariant_is_tenant_bound(): void
    {
        $pdo = $this->runtime();
        $pdo->beginTransaction();
        $this->local($pdo, $this->admin['a']['user'], $this->tenant['a']);
        $pdo->exec('SAVEPOINT rm02_nested');
        $this->local($pdo, $this->admin['b']['user'], $this->tenant['b']);
        $this->assertSame([['id' => $this->tenant['b']]], $this->rows($pdo, 'SELECT id FROM tenants'));
        $pdo->exec('ROLLBACK TO SAVEPOINT rm02_nested');
        $this->assertSame([['id' => $this->tenant['a']]], $this->rows($pdo, 'SELECT id FROM tenants'));
        $pdo->exec('SAVEPOINT rm02_failed');
        $this->local($pdo, $this->admin['b']['user'], $this->tenant['b']);
        try {
            $this->rows($pdo, 'SELECT id FROM users');
            $this->fail('Ungranted global users read succeeded.');
        } catch (PDOException $exception) {
            $this->assertSame('42501', $exception->getCode());
        }
        $pdo->exec('ROLLBACK TO SAVEPOINT rm02_failed');
        $this->assertSame([['id' => $this->tenant['a']]], $this->rows($pdo, 'SELECT id FROM tenants'));
        $pdo->rollBack();
        $this->assertSame(0, $this->visible($pdo, 'tenants'));

        $hostA = app(TenantHostResolver::class)->resolve('rm02-a.'.self::BASE_DOMAIN);
        $runtime = DB::connection('pgsql_tenant_runtime');
        $runtime->beginTransaction();
        try {
            app(TenantStaffContextGuard::class)->activateFromSession($hostA, $this->staffSession($hostA, $this->admin['a']));
            $invariant = app(TenantStaffAdminInvariant::class);
            $invariant->assertRemains($this->tenant['a']);
            try {
                $invariant->assertRemains($this->tenant['b']);
                $this->fail('Last-admin invariant read tenant B rows under a tenant A context.');
            } catch (AuthorizationDeniedException) {
                $this->assertTrue(true);
            }
        } finally {
            $runtime->rollBack();
        }
    }
}
