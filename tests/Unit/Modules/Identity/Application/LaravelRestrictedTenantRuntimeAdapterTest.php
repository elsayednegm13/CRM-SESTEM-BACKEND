<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\RestrictedTenantProbeExecutor;
use App\Modules\Identity\Application\RestrictedTenantProbePlan;
use App\Modules\Identity\Application\LaravelRestrictedTenantRuntimeAdapter;
use App\Modules\Identity\Application\TenantAuthorityAuthenticator;
use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Application\TenantAuthorityRevoker;
use App\Modules\Identity\Application\TenantRuntimeConnectionProvider;
use App\Modules\Identity\Application\TenantRuntimeIdentityAttestor;
use App\Modules\Identity\Application\TenantRestrictedProbeCoordinator;
use App\Modules\Identity\Application\RevokedTenantSessionVerifier;
use App\Modules\Identity\Domain\Exceptions\RestrictedTenantProbeCleanupException;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use LogicException;
use Mockery;
use Tests\TestCase;

final class LaravelRestrictedTenantRuntimeAdapterTest extends TestCase
{
    private const TENANT_A = '019c4a5b-5010-7f00-8a00-50e6e64c335a';
    private const TENANT_B = '019c4a5b-5010-7f00-8a00-50e6e64c336a';
    private const USER = '019c4a5b-5010-7f00-8a00-50e6e64c335b';
    private const MEMBER = '019c4a5b-5010-7f00-8a00-50e6e64c335c';
    private const GENERATION = '019c4a5b-5010-7f00-8a00-50e6e64c335d';
    private const RECORD = '019c4a5b-5010-7f00-8a00-50e6e64c335e';

    public function test_real_adapter_owns_transaction_before_login_and_cleans_authority(): void
    {
        [$adapter, $request, $state] = $this->adapter([
            'attempted' => true,
            'executed' => true,
            'observed_outcome' => 'ALLOWED',
            'row_effects' => 1,
            'postcondition_proved' => true,
        ]);
        $result = TenantRestrictedProbeCoordinator::forRuntimeAdapter($adapter)->authenticateAndExecuteRuntime(
            $this->host(), 'actor@example.test', 'synthetic-password', 'retry', $request,
            $this->plan('create', self::TENANT_A, 'ALLOWED', 1),
        );

        self::assertSame('ADAPTER_OBSERVATION_REQUIRES_INDEPENDENT_VERIFICATION', $result['classification']);
        self::assertSame('create', $result['operation']);
        self::assertSame('ALLOWED', $result['expected_outcome']);
        self::assertSame(1, $result['expected_row_effects']);
        self::assertSame('ALLOWED', $result['observed_outcome']);
        self::assertSame('COMPLETE', $result['cleanup_status']);
        self::assertSame(0, $state->level);
        self::assertSame(['begin', 'authenticate:1', 'execute:1', 'rollback', 'revoke', 'verify-revoked'], $state->events);
        self::assertTrue($result['revoked_session_denied']);
        self::assertNull($request->attributes->get('tenant_staff_context'));
        self::assertNull($request->session()->get('identity.tenant_staff'));
    }

    public function test_real_adapter_rejects_noop_mutation_and_preserves_cleanup(): void
    {
        [$adapter, $request, $state] = $this->adapter([
            'attempted' => true,
            'executed' => true,
            'observed_outcome' => 'ALLOWED',
            'row_effects' => 0,
            'postcondition_proved' => true,
        ]);

        try {
            $adapter->authenticateAndExecute($this->host(), 'actor@example.test', 'synthetic-password', 'retry', $request,
                $this->plan('create', self::TENANT_A, 'ALLOWED', 1));
            self::fail('A no-op mutation cleared the runtime adapter gate.');
        } catch (LogicException $exception) {
            self::assertSame('Restricted tenant probe evidence is incomplete or unexpected.', $exception->getMessage());
        }
        self::assertSame(0, $state->level);
        self::assertSame(['begin', 'authenticate:1', 'execute:1', 'rollback', 'revoke', 'verify-revoked'], $state->events);
    }

    public function test_real_adapter_rejects_cross_tenant_mismatch_before_transaction(): void
    {
        [$adapter, $request, $state] = $this->adapter([
            'attempted' => true, 'executed' => true, 'observed_outcome' => 'DENIED_ZERO_ROWS',
            'row_effects' => 0, 'postcondition_proved' => true,
        ]);
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('actor/tenant mismatch');
        try {
            $adapter->authenticateAndExecute($this->host(), 'actor@example.test', 'synthetic-password', 'retry', $request,
                new RestrictedTenantProbePlan('run-008', 'cross', self::TENANT_B, 'read', 'runtime', 'owned', self::TENANT_A, self::RECORD, 'DENIED_ZERO_ROWS', 0));
        } finally {
            self::assertSame([], $state->events);
        }
    }

    public function test_real_adapter_rejects_swapped_connection_and_rolls_back(): void
    {
        [$adapter, $request, $state] = $this->adapter([
            'attempted' => true, 'executed' => true, 'observed_outcome' => 'ALLOWED',
            'row_effects' => 1, 'postcondition_proved' => true,
        ], true);
        try {
            $adapter->authenticateAndExecute($this->host(), 'actor@example.test', 'synthetic-password', 'retry', $request,
                $this->plan('read', self::TENANT_A, 'ALLOWED', 1));
            self::fail('A swapped connection was accepted.');
        } catch (LogicException $exception) {
            self::assertStringContainsString('connection affinity', $exception->getMessage());
        }
        self::assertSame(0, $state->level);
        self::assertSame(['begin', 'authenticate:1', 'rollback', 'revoke', 'verify-revoked'], $state->events);
    }

    public function test_primary_and_cleanup_failures_are_both_preserved(): void
    {
        [$adapter, $request] = $this->adapter([
            'attempted' => true, 'executed' => true, 'observed_outcome' => 'ALLOWED',
            'row_effects' => 0, 'postcondition_proved' => true,
        ], false, true);
        try {
            $adapter->authenticateAndExecute($this->host(), 'actor@example.test', 'synthetic-password', 'retry', $request,
                $this->plan('create', self::TENANT_A, 'ALLOWED', 1));
            self::fail('Combined failure was lost.');
        } catch (RestrictedTenantProbeCleanupException $exception) {
            self::assertSame(LogicException::class, $exception->primaryType);
            self::assertSame(LogicException::class, $exception->cleanupType());
            self::assertSame('cleanup-failed', $exception->cleanup->getMessage());
            self::assertInstanceOf(LogicException::class, $exception->getPrevious());
        }
    }

    /** @return array{0:LaravelRestrictedTenantRuntimeAdapter,1:Request,2:object} */
    private function adapter(array $observation, bool $swap = false, bool $cleanupFails = false): array
    {
        $state = (object) ['level' => 0, 'events' => []];
        $connection = Mockery::mock(Connection::class);
        $connection->shouldReceive('transactionLevel')->andReturnUsing(fn (): int => $state->level);
        $connection->shouldReceive('beginTransaction')->zeroOrMoreTimes()->andReturnUsing(function () use ($state): void {
            $state->level = 1; $state->events[] = 'begin';
        });
        $connection->shouldReceive('rollBack')->zeroOrMoreTimes()->andReturnUsing(function () use ($state): void {
            $state->level = 0; $state->events[] = 'rollback';
        });
        $other = Mockery::mock(Connection::class);
        $calls = 0;
        $provider = new class($connection, $other, $swap, $calls) implements TenantRuntimeConnectionProvider {
            public function __construct(private Connection $connection, private Connection $other, private bool $swap, private int &$calls) {}
            public function connection(): Connection { $this->calls++; return $this->swap && $this->calls > 1 ? $this->other : $this->connection; }
        };
        $authenticator = new class($connection, $state, self::USER, self::MEMBER, self::GENERATION) implements TenantAuthorityAuthenticator {
            public function __construct(private Connection $connection, private object $state, private string $userId, private string $membershipId, private string $generation) {}
            public function authenticate(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request): TenantStaffUser
            {
                $this->state->events[] = 'authenticate:'.$this->connection->transactionLevel();
                if ($this->connection->transactionLevel() !== 1) { throw new LogicException('login-before-transaction'); }
                $request->session()->migrate(true);
                $request->attributes->set('tenant_staff_context', new TenantStaffContext($host->tenantId, $host->hostname, $this->userId, $this->membershipId, 1, 1));
                $request->attributes->set('tenant_staff_runtime_connection_id', spl_object_id($this->connection));
                $request->attributes->set('tenant_staff_authority_cleanup', ['hash' => str_repeat('a', 64), 'generation' => $this->generation]);
                $request->session()->put('identity.tenant_staff', ['authority_generation' => $this->generation]);
                return new TenantStaffUser;
            }
        };
        $executor = new class($connection, $state, $observation) implements RestrictedTenantProbeExecutor {
            public function __construct(private Connection $expected, private object $state, private array $observation) {}
            public function execute(Connection $connection, TenantStaffContext $context, RestrictedTenantProbePlan $plan): array
            {
                if ($connection !== $this->expected) { throw new LogicException('wrong-executor-connection'); }
                $this->state->events[] = 'execute:'.$connection->transactionLevel();
                return $this->observation;
            }
        };
        $revoker = new class($state, $cleanupFails) implements TenantAuthorityRevoker {
            public function __construct(private object $state, private bool $fails) {}
            public function revokeHash(string $sessionHash, string $generation): void { $this->state->events[] = 'revoke'; if ($this->fails) { throw new LogicException('cleanup-failed'); } }
        };
        $identity = new class implements TenantRuntimeIdentityAttestor {
            public function attest(Connection $connection): array
            {
                return [
                    'principal' => 'dl_core_truntime',
                    'database' => 'dcrm_p1p2_owned',
                    'system_identifier' => '7705999999999999999',
                    'database_oid' => 50123,
                    'backend_pid' => 42,
                ];
            }
        };
        $revokedSessions = new class($state) implements RevokedTenantSessionVerifier {
            public function __construct(private object $state) {}
            public function assertDenied(TenantHostContext $host, Request $request, Connection $connection): void
            {
                $this->state->events[] = 'verify-revoked';
                if ($connection->transactionLevel() !== 0) { throw new LogicException('verification-before-rollback'); }
            }
        };

        return [new LaravelRestrictedTenantRuntimeAdapter(new TenantAuthorityBridge($authenticator), $provider, $executor, $revoker, $identity, $revokedSessions), $this->request(), $state];
    }

    private function request(): Request
    {
        $request = Request::create('/', 'POST');
        $session = new Store('runtime-adapter', new ArraySessionHandler(60));
        $session->start();
        $request->setLaravelSession($session);
        return $request;
    }

    private function host(): TenantHostContext
    {
        return new TenantHostContext(self::TENANT_A, 'a', 'a.test', 'test', 'LOCAL_TEST');
    }

    private function plan(string $operation, string $target, string $outcome, int $effects): RestrictedTenantProbePlan
    {
        return new RestrictedTenantProbePlan('run-008', 'case-'.$operation, self::TENANT_A, $operation, 'runtime', 'owned', $target, self::RECORD, $outcome, $effects);
    }
}
