<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\LaravelRestrictedTenantProbeExecutor;
use App\Modules\Identity\Application\RestrictedTenantProbePlan;
use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Mockery;
use PDOException;
use Tests\TestCase;

final class LaravelRestrictedTenantProbeExecutorTest extends TestCase
{
    private const TENANT_A = '019c4a5b-5010-7f00-8a00-50e6e64c335a';
    private const TENANT_B = '019c4a5b-5010-7f00-8a00-50e6e64c336a';
    private const USER = '019c4a5b-5010-7f00-8a00-50e6e64c335b';
    private const MEMBER = '019c4a5b-5010-7f00-8a00-50e6e64c335c';
    private const RECORD = '019c4a5b-5010-7f00-8a00-50e6e64c335e';

    public function test_create_uses_fixed_parameterized_sql_and_proves_row_effect(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('transactionLevel')->once()->andReturn(1);
        $connection->shouldReceive('statement')->once()->with('SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('statement')->once()->with('RELEASE SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('affectingStatement')->once()
            ->with(Mockery::on(fn (string $sql): bool => str_starts_with($sql, 'INSERT INTO public.leads')), Mockery::type('array'))
            ->andReturn(1);
        $connection->shouldReceive('selectOne')->once()
            ->with(Mockery::on(fn (string $sql): bool => str_starts_with($sql, 'SELECT count(*)::int')), [self::TENANT_A, self::RECORD])
            ->andReturn((object) ['aggregate' => 1]);

        $result = (new LaravelRestrictedTenantProbeExecutor)->execute(
            $connection,
            $this->context(),
            $this->plan('create', self::TENANT_A, 'ALLOWED', 1),
        );
        self::assertSame('ALLOWED', $result['observed_outcome']);
        self::assertSame(1, $result['row_effects']);
        self::assertTrue($result['postcondition_proved']);
    }

    public function test_cross_tenant_read_is_denied_as_zero_rows(): void
    {
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('transactionLevel')->once()->andReturn(1);
        $connection->shouldReceive('statement')->once()->with('SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('statement')->once()->with('RELEASE SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('selectOne')->twice()->andReturn((object) ['aggregate' => 0]);

        $result = (new LaravelRestrictedTenantProbeExecutor)->execute(
            $connection,
            $this->context(),
            $this->plan('read', self::TENANT_B, 'DENIED_ZERO_ROWS', 0),
        );
        self::assertSame('DENIED_ZERO_ROWS', $result['observed_outcome']);
        self::assertSame(0, $result['row_effects']);
        self::assertTrue($result['postcondition_proved']);
    }

    public function test_cross_tenant_insert_preserves_sqlstate_42501_classification(): void
    {
        $previous = new PDOException('permission denied');
        $previous->errorInfo = ['42501', 7, 'permission denied'];
        $exception = new QueryException('pgsql_tenant_runtime', 'INSERT', [], $previous);
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('transactionLevel')->once()->andReturn(1);
        $connection->shouldReceive('statement')->once()->with('SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('statement')->once()->with('ROLLBACK TO SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('statement')->once()->with('RELEASE SAVEPOINT dcrm008_restricted_probe')->andReturnTrue();
        $connection->shouldReceive('affectingStatement')->once()->andThrow($exception);
        $connection->shouldReceive('selectOne')->once()->andReturn((object) ['aggregate' => 0]);

        $result = (new LaravelRestrictedTenantProbeExecutor)->execute(
            $connection,
            $this->context(),
            $this->plan('create', self::TENANT_B, 'DENIED_SQLSTATE_42501', 0),
        );
        self::assertSame('DENIED_SQLSTATE_42501', $result['observed_outcome']);
        self::assertSame(0, $result['row_effects']);
        self::assertTrue($result['postcondition_proved']);
    }

    private function context(): TenantStaffContext
    {
        return new TenantStaffContext(self::TENANT_A, 'a.test', self::USER, self::MEMBER, 1, 1);
    }

    private function plan(string $operation, string $target, string $outcome, int $effects): RestrictedTenantProbePlan
    {
        return new RestrictedTenantProbePlan('run-008', 'case-'.$operation, self::TENANT_A, $operation, 'runtime', 'owned', $target, self::RECORD, $outcome, $effects);
    }
}
