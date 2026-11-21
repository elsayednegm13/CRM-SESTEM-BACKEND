<?php

namespace Tests\Feature\Tenancy;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class TenantStaffRlsContextTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (config('database.connections.pgsql_tenant_runtime.database') !== 'daleel_fnd_id02_auth_test') {
            self::markTestSkipped('The test-only FND-ID-02 PostgreSQL target is not configured.');
        }
    }

    public function test_runtime_is_non_owner_and_nobypass_and_uses_minimum_staff_columns(): void
    {
        $connection = DB::connection('pgsql_tenant_runtime');
        $identity = $connection->selectOne(<<<'SQL'
            SELECT session_user,
                   current_user,
                   current_database(),
                   r.rolsuper,
                   r.rolbypassrls,
                   r.rolcanlogin,
                   pg_catalog.has_column_privilege(session_user, 'public.tenant_staff_users', 'password_hash', 'SELECT') AS can_read_password_hash,
                   pg_catalog.pg_get_userbyid(c.relowner) = session_user AS owns_staff_table,
                   pg_catalog.pg_backend_pid() AS backend_pid
            FROM pg_catalog.pg_roles r
            CROSS JOIN pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE r.rolname = session_user AND n.nspname = 'public' AND c.relname = 'tenant_staff_users'
        SQL);

        self::assertNotNull($identity);
        self::assertFalse((bool) $identity->rolsuper);
        self::assertFalse((bool) $identity->rolbypassrls);
        self::assertTrue((bool) $identity->rolcanlogin);
        self::assertFalse((bool) $identity->can_read_password_hash);
        self::assertFalse((bool) $identity->owns_staff_table);
    }

    public function test_rls_context_is_transaction_local_and_filters_a_b_on_one_runtime_connection(): void
    {
        $connection = DB::connection('pgsql_tenant_runtime');
        $tenantA = (string) env('FND_ID02_FIXTURE_TENANT_A_ID', '');
        $tenantB = (string) env('FND_ID02_FIXTURE_TENANT_B_ID', '');
        $userA = (string) env('FND_ID02_FIXTURE_USER_A_ID', '');
        $userB = (string) env('FND_ID02_FIXTURE_USER_B_ID', '');
        if ($tenantA === '' || $tenantB === '' || $userA === '' || $userB === '') {
            self::markTestSkipped('Synthetic FND-ID-02 fixture identity values are absent.');
        }

        self::assertSame([], $connection->select('SELECT id FROM public.tenant_staff_users WHERE tenant_id = ?', [$tenantA]));
        $pid = null;
        $visibleA = $connection->transaction(function () use ($connection, $tenantA, $userA, &$pid): array {
            $this->setContext($connection, $tenantA, $userA);
            $pid = $connection->selectOne('SELECT pg_catalog.pg_backend_pid() AS pid')->pid;
            return array_column($connection->select('SELECT id FROM public.tenant_staff_users WHERE tenant_id = ?', [$tenantA]), 'id');
        });
        self::assertContains($userA, $visibleA);
        self::assertSame([], $connection->select('SELECT id FROM public.tenant_staff_users WHERE tenant_id = ?', [$tenantA]));
        self::assertFalse(in_array($tenantA, array_column($connection->select("SELECT pg_catalog.current_setting('app.tenant_id', true) AS tenant_id"), 'tenant_id'), true));

        $visibleB = $connection->transaction(function () use ($connection, $tenantB, $userB): array {
            $this->setContext($connection, $tenantB, $userB);
            return array_column($connection->select('SELECT id FROM public.tenant_staff_users WHERE tenant_id = ?', [$tenantB]), 'id');
        });
        self::assertContains($userB, $visibleB);
        self::assertSame([], $connection->select('SELECT id FROM public.tenant_staff_users WHERE tenant_id = ?', [$tenantB]));

        $after = $connection->selectOne('SELECT pg_catalog.pg_backend_pid() AS pid');
        self::assertSame((string) $pid, (string) $after->pid);
    }

    private function setContext($connection, string $tenantId, string $userId): void
    {
        $connection->selectOne("SELECT pg_catalog.set_config('app.context_mode', 'TENANT', true)");
        $connection->selectOne("SELECT pg_catalog.set_config('app.tenant_id', ?, true)", [$tenantId]);
        $connection->selectOne("SELECT pg_catalog.set_config('app.user_id', ?, true)", [$userId]);
    }
}
