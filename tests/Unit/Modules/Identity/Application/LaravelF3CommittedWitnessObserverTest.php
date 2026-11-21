<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\LaravelF3CommittedWitnessObserver;
use App\Modules\Identity\Application\RevokedTenantSessionVerifier;
use App\Modules\Identity\Application\TenantAuthorityAuthenticator;
use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Application\TenantAuthorityRevoker;
use App\Modules\Identity\Application\TenantRuntimeConnectionProvider;
use App\Modules\Identity\Application\TenantRuntimeIdentityAttestor;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use LogicException;
use Tests\TestCase;

final class LaravelF3CommittedWitnessObserverTest extends TestCase
{
    public function test_observes_committed_witness_on_fresh_read_only_bound_connection_then_revokes(): void
    {
        $tenantA = '11111111-1111-4111-8111-111111111111';
        $tenantB = '22222222-2222-4222-8222-222222222222';
        $observer = '11111111-1111-4111-8111-111111111113';
        $admin = '11111111-1111-4111-8111-111111111112';
        $connection = $this->connection($tenantA, $tenantB);
        $request = $this->request();
        $host = new TenantHostContext($tenantA, 'tenant-a', 'tenant-a.daleel.localhost', 'daleel.localhost', 'LOCAL_TEST');
        $authenticator = new class($connection, $observer, $tenantA) implements TenantAuthorityAuthenticator {
            public function __construct(private Connection $connection, private string $membership, private string $tenant) {}
            public function authenticate(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request): TenantStaffUser
            {
                $request->session()->migrate(true);
                $request->session()->put('identity.tenant_staff', ['authority_generation' => 'gen-2']);
                $request->attributes->set('tenant_staff_context', new TenantStaffContext($this->tenant, $host->hostname, '11111111-1111-4111-8111-111111111114', $this->membership, 1, 1));
                $request->attributes->set('tenant_staff_runtime_connection_id', spl_object_id($this->connection));
                $request->attributes->set('tenant_staff_authority_cleanup', ['hash' => str_repeat('a', 64), 'generation' => 'gen-2']);
                return new TenantStaffUser;
            }
        };
        $provider = new class($connection) implements TenantRuntimeConnectionProvider {
            public function __construct(private Connection $connection) {}
            public function connection(): Connection { return $this->connection; }
        };
        $identity = new class implements TenantRuntimeIdentityAttestor {
            public function attest(Connection $connection): array
            {
                return ['principal' => 'dl_core_truntime', 'database' => 'dcrm_p1p2_test', 'system_identifier' => '7706999999999999999', 'database_oid' => 16384, 'backend_pid' => 902];
            }
        };
        $revoker = new class implements TenantAuthorityRevoker {
            public int $calls = 0;
            public function revokeHash(string $sessionHash, string $generation): void { $this->calls++; }
        };
        $revoked = new class implements RevokedTenantSessionVerifier {
            public int $calls = 0;
            public function assertDenied(TenantHostContext $host, Request $request, Connection $connection): void { $this->calls++; }
        };
        $service = new LaravelF3CommittedWitnessObserver(new TenantAuthorityBridge($authenticator), $provider, $identity, $revoker, $revoked);

        $result = $service->observe(
            $host, 'observer@example.invalid', 'secret', '33333333-3333-4333-8333-333333333333', $request,
            $tenantA, $observer, $admin, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', $tenantB,
            'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '900001', 901, 'run-test-001',
        );

        self::assertSame('F3_COMMITTED_WITNESS_INDEPENDENTLY_OBSERVED', $result['classification']);
        self::assertSame(1, $result['own_witness_count']);
        self::assertSame(0, $result['foreign_witness_count']);
        self::assertTrue($result['commit_visible_in_snapshot']);
        self::assertTrue($result['transaction_read_only']);
        self::assertSame('COMPLETE', $result['cleanup_status']);
        self::assertSame(1, $revoker->calls);
        self::assertSame(1, $revoked->calls);
        self::assertSame(0, $connection->transactionLevel());
    }

    public function test_rejects_fixture_backend_reuse_and_still_rolls_back(): void
    {
        $this->expectException(LogicException::class);
        $tenantA = '11111111-1111-4111-8111-111111111111';
        $tenantB = '22222222-2222-4222-8222-222222222222';
        $connection = $this->connection($tenantA, $tenantB);
        $request = $this->request();
        $host = new TenantHostContext($tenantA, 'tenant-a', 'tenant-a.daleel.localhost', 'daleel.localhost', 'LOCAL_TEST');
        $authenticator = new class($connection, $tenantA) implements TenantAuthorityAuthenticator {
            public function __construct(private Connection $connection, private string $tenant) {}
            public function authenticate(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request): TenantStaffUser
            {
                $request->session()->migrate(true);
                $request->session()->put('identity.tenant_staff', ['authority_generation' => 'gen-2']);
                $request->attributes->set('tenant_staff_context', new TenantStaffContext($this->tenant, $host->hostname, '11111111-1111-4111-8111-111111111114', '11111111-1111-4111-8111-111111111113', 1, 1));
                $request->attributes->set('tenant_staff_runtime_connection_id', spl_object_id($this->connection));
                return new TenantStaffUser;
            }
        };
        $provider = new class($connection) implements TenantRuntimeConnectionProvider {
            public function __construct(private Connection $connection) {}
            public function connection(): Connection { return $this->connection; }
        };
        $identity = new class implements TenantRuntimeIdentityAttestor {
            public function attest(Connection $connection): array { return ['principal' => 'dl_core_truntime', 'database' => 'db', 'system_identifier' => '1', 'database_oid' => 1, 'backend_pid' => 901]; }
        };
        $revoker = new class implements TenantAuthorityRevoker { public function revokeHash(string $sessionHash, string $generation): void {} };
        $revoked = new class implements RevokedTenantSessionVerifier { public function assertDenied(TenantHostContext $host, Request $request, Connection $connection): void {} };
        $service = new LaravelF3CommittedWitnessObserver(new TenantAuthorityBridge($authenticator), $provider, $identity, $revoker, $revoked);
        try {
            $service->observe($host, 'observer@example.invalid', 'secret', '33333333-3333-4333-8333-333333333333', $request,
                $tenantA, '11111111-1111-4111-8111-111111111113', '11111111-1111-4111-8111-111111111112',
                'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', $tenantB, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', '900001', 901, 'run-test-001');
        } finally {
            self::assertSame(0, $connection->transactionLevel());
        }
    }

    private function request(): Request
    {
        $request = Request::create('https://tenant-a.daleel.localhost/internal', 'POST');
        $session = new Store('f3-observer-unit', new ArraySessionHandler(900));
        $session->start();
        $request->setLaravelSession($session);
        return $request;
    }

    private function connection(string $tenantA, string $tenantB): Connection
    {
        $level = 0;
        $connection = $this->createMock(Connection::class);
        $connection->method('transactionLevel')->willReturnCallback(static function () use (&$level): int { return $level; });
        $connection->method('beginTransaction')->willReturnCallback(static function () use (&$level): void { $level = 1; });
        $connection->method('rollBack')->willReturnCallback(static function () use (&$level): void { $level = 0; });
        $connection->method('statement')->with('SET TRANSACTION READ ONLY')->willReturn(true);
        $connection->method('selectOne')->willReturnCallback(static function (string $sql, array $bindings) use ($tenantA, $tenantB): object {
            if (str_contains($sql, 'pg_visible_in_snapshot')) {
                return (object) ['commit_visible' => true, 'snapshot' => '900002:900002:', 'transaction_read_only' => 'on'];
            }
            return (object) ['aggregate' => $bindings[0] === $tenantA ? 1 : ($bindings[0] === $tenantB ? 0 : -1)];
        });
        return $connection;
    }
}
