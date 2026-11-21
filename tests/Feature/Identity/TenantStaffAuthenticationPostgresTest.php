<?php

namespace Tests\Feature\Identity;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class TenantStaffAuthenticationPostgresTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (config('database.connections.pgsql_tenant_auth.database') !== 'daleel_fnd_id02_auth_test') {
            self::markTestSkipped('The test-only FND-ID-02 PostgreSQL target is not configured.');
        }
    }

    public function test_restricted_lookup_binds_duplicate_email_to_the_exact_registered_host(): void
    {
        $this->assertIsolatedTarget('pgsql_tenant_auth');
        $email = (string) env('FND_ID02_FIXTURE_EMAIL', '');
        $hostA = (string) env('FND_ID02_FIXTURE_HOST_A', '');
        $hostB = (string) env('FND_ID02_FIXTURE_HOST_B', '');
        if ($email === '' || $hostA === '' || $hostB === '') {
            self::markTestSkipped('Synthetic FND-ID-02 fixture host/email values are absent.');
        }

        $a = DB::connection('pgsql_tenant_auth')->selectOne(
            'SELECT tenant_id, staff_user_id, membership_id FROM public.lookup_tenant_staff_credentials(?, ?, ?, ?)',
            [$hostA, 'id02.localhost', 'LOCAL_TEST', $email],
        );
        $b = DB::connection('pgsql_tenant_auth')->selectOne(
            'SELECT tenant_id, staff_user_id, membership_id FROM public.lookup_tenant_staff_credentials(?, ?, ?, ?)',
            [$hostB, 'id02.localhost', 'LOCAL_TEST', $email],
        );

        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertNotSame($a->tenant_id, $b->tenant_id);
        self::assertNotSame($a->staff_user_id, $b->staff_user_id);
        self::assertSame((string) env('FND_ID02_FIXTURE_USER_A_ID'), $a->staff_user_id);
        self::assertSame((string) env('FND_ID02_FIXTURE_USER_B_ID'), $b->staff_user_id);
        self::assertNull(DB::connection('pgsql_tenant_auth')->selectOne(
            'SELECT tenant_id, staff_user_id FROM public.lookup_tenant_staff_credentials(?, ?, ?, ?)',
            ['unknown.id02.localhost', 'id02.localhost', 'LOCAL_TEST', $email],
        ));
    }

    public function test_auth_client_can_execute_only_the_narrow_lookup_not_read_staff_tables(): void
    {
        $this->assertIsolatedTarget('pgsql_tenant_auth');
        $connection = DB::connection('pgsql_tenant_auth');
        $acl = $connection->selectOne(<<<'SQL'
            SELECT session_user,
                   current_user,
                   pg_catalog.has_function_privilege(session_user, 'public.lookup_tenant_staff_credentials(text,text,text,text)', 'EXECUTE') AS can_execute,
                   pg_catalog.has_table_privilege(session_user, 'public.tenant_staff_users', 'SELECT') AS can_select_staff
        SQL);
        self::assertTrue((bool) $acl->can_execute);
        self::assertFalse((bool) $acl->can_select_staff);

        try {
            $connection->select('SELECT id FROM public.tenant_staff_users LIMIT 1');
            self::fail('The pre-auth client must not have direct staff-table SELECT.');
        } catch (QueryException $exception) {
            self::assertSame('42501', (string) ($exception->errorInfo[0] ?? $exception->getCode()));
        }
    }

    private function assertIsolatedTarget(string $connectionName): void
    {
        $connection = DB::connection($connectionName);
        $identity = $connection->selectOne(<<<'SQL'
            SELECT current_database() AS database,
                   inet_server_addr()::text AS server_address,
                   inet_server_port() AS server_port,
                   session_user
        SQL);
        self::assertSame('daleel_fnd_id02_auth_test', $identity->database);
        self::assertNotSame('', (string) $identity->server_address);
        self::assertGreaterThan(0, (int) $identity->server_port);
        self::assertSame((string) config('database.connections.'.$connectionName.'.username'), $identity->session_user);
        $attestedSystemIdentifier = (string) env('FND_ID02_EXPECTED_SYSTEM_IDENTIFIER', '');
        self::assertNotSame('', $attestedSystemIdentifier, 'A separate superuser metadata attestation must be provided.');
        self::assertNotContains($attestedSystemIdentifier, [
            '7694788471752536103',
            '7694796524329697318',
            '7695817420231278630',
        ]);
    }
}
