<?php
declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\TenantAuthorityAuthenticator;
use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use LogicException;
use Tests\Support\Identity\OfflineF3LifecycleOrchestrator;
use Tests\Support\Identity\StatefulAuthorityAffinityTransport;
use Tests\Support\Identity\StatefulTenantProbeOrchestrator;
use Tests\TestCase;

final class OfflineF3LifecycleOrchestratorTest extends TestCase
{
    private function request(): Request
    {
        $request = Request::create('/', 'POST');
        $session = new Store('offline-f3', new ArraySessionHandler(60));
        $session->start();
        $request->setLaravelSession($session);
        return $request;
    }

    private function host(): TenantHostContext
    {
        return new TenantHostContext('019c4a5b-5010-7f00-8a00-50e6e64c335a', 'a', 'a.test', 'test', 'LOCAL_TEST');
    }

    private function lifecycle(StatefulAuthorityAffinityTransport $transport): OfflineF3LifecycleOrchestrator
    {
        $generation = '019c4a5b-5010-7f00-8a00-50e6e64c335d';
        $authenticator = new class($generation) implements TenantAuthorityAuthenticator {
            public function __construct(private readonly string $generation) {}
            public function authenticate(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request): TenantStaffUser
            {
                $request->session()->migrate(true);
                $request->attributes->set('tenant_staff_context', new TenantStaffContext($host->tenantId, $host->hostname, '019c4a5b-5010-7f00-8a00-50e6e64c335b', '019c4a5b-5010-7f00-8a00-50e6e64c335c', 1, 1));
                $request->session()->put('identity.tenant_staff', ['authority_generation' => $this->generation]);
                return new TenantStaffUser;
            }
        };
        return new OfflineF3LifecycleOrchestrator(
            new TenantAuthorityBridge($authenticator),
            new StatefulTenantProbeOrchestrator($transport, 'offline-f3-run'),
            $transport,
        );
    }

    /** @return array<string,mixed> */
    private function environment(): array
    {
        return ['run_id' => 'offline-f3-run', 'task_owned' => true, 'container_id' => str_repeat('a', 64), 'container_name' => 'dcrm-p1p2-ownerchain-offline-008-pg', 'database' => 'dcrm_p1p2_offline_008', 'system_identifier' => '7705999999999999008', 'published_ports' => 0, 'migration_ledger' => true, 'force_rls' => true, 'restricted_grant_denied' => true, 'restricted_principal' => 'dl_core_truntime', 'membership_active' => true, 'evidence_nonce' => 'nonce-1', 'capture_state' => 'CAPTURED', 'timeout_state' => 'WITHIN_BOUND', 'cancelled' => false, 'evidence_terminal' => 'COMPLETE', 'role_cleanup' => true, 'container_stopped' => true];
    }

    /** @return list<array<string,mixed>> */
    private function probes(): array
    {
        $generation = '019c4a5b-5010-7f00-8a00-50e6e64c335d';
        return [
            ['case_id' => 'F4-A-read', 'actor' => 'A', 'tenant' => 'A', 'generation' => $generation, 'connection' => 'c1', 'transaction' => 't1', 'operation' => 'read', 'target' => 'A'],
            ['case_id' => 'F4-A-create', 'actor' => 'A', 'tenant' => 'A', 'generation' => $generation, 'connection' => 'c1', 'transaction' => 't2', 'operation' => 'create', 'target' => 'A', 'value' => 'created'],
            ['case_id' => 'F4-A-update', 'actor' => 'A', 'tenant' => 'A', 'generation' => $generation, 'connection' => 'c1', 'transaction' => 't3', 'operation' => 'update', 'target' => 'A', 'value' => 'updated'],
        ];
    }

    public function test_c05_positive_invoked_lifecycle_is_explicitly_offline_only(): void
    {
        $transport = new StatefulAuthorityAffinityTransport;
        $result = $this->lifecycle($transport)->run($this->environment(), $this->host(), $this->request(), $this->probes());
        self::assertSame('OFFLINE_SIMULATION_NOT_RUNTIME', $result['classification']);
        self::assertSame('F3_CONTRACT_VERIFIED_BY_ADAPTER', $result['f3_classification']);
        self::assertCount(3, $result['records']);
        self::assertSame(['transaction' => null, 'bound' => null], $transport->state());
    }

    public function test_c05_environment_failures_fail_closed_without_probe_execution(): void
    {
        foreach (['run_id' => 'wrong-run', 'task_owned' => false, 'container_id' => 'wrong', 'container_name' => 'wrong-pg', 'database' => 'daleel_local_dev', 'system_identifier' => 'wrong', 'published_ports' => 1, 'migration_ledger' => false, 'force_rls' => false, 'restricted_grant_denied' => false, 'restricted_principal' => 'postgres', 'membership_active' => false, 'capture_state' => 'FAULT', 'timeout_state' => 'TIMED_OUT', 'cancelled' => true] as $field => $value) {
            $transport = new StatefulAuthorityAffinityTransport;
            $environment = $this->environment();
            $environment[$field] = $value;
            try {
                $this->lifecycle($transport)->run($environment, $this->host(), $this->request(), $this->probes());
                self::fail($field . ' accepted');
            } catch (LogicException $exception) {
                self::assertStringStartsWith('offline-f3-guard-', $exception->getMessage());
                self::assertSame([], $transport->events);
            }
        }
    }

    public function test_c05_cross_tenant_wrong_connection_generation_revocation_and_replay_fail_closed(): void
    {
        $generation = '019c4a5b-5010-7f00-8a00-50e6e64c335d';
        foreach ([
            'cross' => static fn (array $p): array => array_replace($p, ['target' => 'B']),
            'forged-context' => static fn (array $p): array => array_replace($p, ['actor' => 'B']),
            'wrong-connection' => static fn (array $p): array => array_replace($p, ['bind_connection' => 'other']),
            'wrong-generation' => static fn (array $p): array => array_replace($p, ['generation' => 'wrong']),
        ] as $case => $mutate) {
            $transport = new StatefulAuthorityAffinityTransport;
            $probes = $this->probes(); $probes = [$mutate($probes[0])];
            try {$this->lifecycle($transport)->run($this->environment(), $this->host(), $this->request(), $probes); self::fail($case . ' accepted');} catch (LogicException) {self::assertSame(['transaction' => null, 'bound' => null], $transport->state());}
        }
        $transport = new StatefulAuthorityAffinityTransport; $transport->revoke($generation);
        try {$this->lifecycle($transport)->run($this->environment(), $this->host(), $this->request(), [$this->probes()[0]]); self::fail('revoked accepted');} catch (LogicException) {self::assertSame(['transaction' => null, 'bound' => null], $transport->state());}
        $transport = new StatefulAuthorityAffinityTransport; $lifecycle = $this->lifecycle($transport); $request = $this->request(); $one = [$this->probes()[0]];
        $lifecycle->run($this->environment(), $this->host(), $request, $one);
        try {$lifecycle->run($this->environment(), $this->host(), $request, $one); self::fail('replay accepted');} catch (LogicException $e) {self::assertSame('offline-f3-evidence-replayed', $e->getMessage());}
    }
}
