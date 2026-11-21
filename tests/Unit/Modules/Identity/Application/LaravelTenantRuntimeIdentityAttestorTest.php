<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\LaravelTenantRuntimeIdentityAttestor;
use Illuminate\Database\Connection;
use LogicException;
use Mockery;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

final class LaravelTenantRuntimeIdentityAttestorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('f3_acceptance.expected_runtime_principal', 'dl_core_truntime');
        config()->set('f3_acceptance.expected_database', 'dcrm_p1p2_owned');
        config()->set('f3_acceptance.expected_system_identifier', '7705999999999999999');
        config()->set('f3_acceptance.expected_database_oid', '50123');
    }

    public function test_accepts_exact_restricted_session_identity(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('selectOne')->once()->with(Mockery::on(
            fn (string $sql): bool => str_contains($sql, 'WITH RECURSIVE memberships')
                && str_contains($sql, "'public.tenant_staff_users'::regclass")
                && str_contains($sql, "'public.tenant_staff_memberships'::regclass")
                && str_contains($sql, 'pg_catalog.pg_control_system()')
                && str_contains($sql, 'pg_catalog.pg_database')
        ))->andReturn((object) [
            'current_user' => 'dl_core_truntime', 'session_user' => 'dl_core_truntime',
            'database' => 'dcrm_p1p2_owned', 'system_identifier' => '7705999999999999999',
            'database_oid' => 50123, 'backend_pid' => 42, 'rolsuper' => false,
            'rolbypassrls' => false, 'rolcreaterole' => false, 'rolcreatedb' => false,
            'owns_probed_table' => false, 'has_privileged_membership' => false,
        ]);
        self::assertSame(
            ['principal' => 'dl_core_truntime', 'database' => 'dcrm_p1p2_owned',
                'system_identifier' => '7705999999999999999', 'database_oid' => 50123, 'backend_pid' => 42],
            (new LaravelTenantRuntimeIdentityAttestor)->attest($connection),
        );
    }

    #[DataProvider('rejectedIdentities')]
    public function test_rejects_wrong_or_privileged_identity(object $identity): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('selectOne')->once()->andReturn($identity);
        $this->expectException(LogicException::class);
        (new LaravelTenantRuntimeIdentityAttestor)->attest($connection);
    }

    public static function rejectedIdentities(): array
    {
        return [
            'wrong role' => [self::identity(['current_user' => 'dl_truntime', 'session_user' => 'dl_truntime'])],
            'set role' => [self::identity(['session_user' => 'postgres'])],
            'wrong database' => [self::identity(['database' => 'daleel_local_dev'])],
            'wrong system identifier' => [self::identity(['system_identifier' => '7705888888888888888'])],
            'wrong database oid' => [self::identity(['database_oid' => 50124])],
            'invalid backend' => [self::identity(['backend_pid' => 0])],
            'superuser' => [self::identity(['rolsuper' => true])],
            'bypass rls' => [self::identity(['rolbypassrls' => true])],
            'create role' => [self::identity(['rolcreaterole' => true])],
            'create db' => [self::identity(['rolcreatedb' => true])],
            'table owner' => [self::identity(['owns_probed_table' => true])],
            'privileged membership' => [self::identity(['has_privileged_membership' => true])],
        ];
    }

    private static function identity(array $overrides): object
    {
        return (object) array_replace([
            'current_user' => 'dl_core_truntime', 'session_user' => 'dl_core_truntime',
            'database' => 'dcrm_p1p2_owned', 'system_identifier' => '7705999999999999999',
            'database_oid' => 50123, 'backend_pid' => 42, 'rolsuper' => false,
            'rolbypassrls' => false, 'rolcreaterole' => false, 'rolcreatedb' => false,
            'owns_probed_table' => false, 'has_privileged_membership' => false,
        ], $overrides);
    }
}
