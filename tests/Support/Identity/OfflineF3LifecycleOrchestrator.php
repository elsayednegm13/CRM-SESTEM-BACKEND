<?php
declare(strict_types=1);

namespace Tests\Support\Identity;

use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\Request;
use LogicException;

/**
 * Test-only F0-F5 composition. It invokes the C02 bridge and C04 probe model,
 * but it never opens a database connection or attests a real container.
 */
final class OfflineF3LifecycleOrchestrator
{
    /** @var array<string, true> */
    private array $evidenceNonces = [];
    public function __construct(
        private readonly TenantAuthorityBridge $bridge,
        private readonly StatefulTenantProbeOrchestrator $probes,
        private readonly StatefulAuthorityAffinityTransport $transport,
    ) {
    }

    /** @param array<string,mixed> $environment @param list<array<string,mixed>> $probes */
    public function run(array $environment, TenantHostContext $host, Request $request, array $probes): array
    {
        $this->assertEnvironment($environment); // F0-F2 fake-native source guard.
        $nonce = (string) $environment['evidence_nonce'];
        if (isset($this->evidenceNonces[$nonce])) {
            throw new LogicException('offline-f3-evidence-replayed');
        }
        $this->evidenceNonces[$nonce] = true;
        $authority = $this->bridge->authenticateAndBind($host, 'offline@example.test', 'not-a-secret', 'offline-retry', $request);
        $generation = $authority['authority_generation'];
        $records = [];

        foreach ($probes as $probe) {
            if (($probe['generation'] ?? null) !== $generation) {
                throw new LogicException('offline-f3-authority-generation-mismatch');
            }
            $records[] = $this->probes->execute(
                (string) ($probe['case_id'] ?? ''), (string) ($probe['actor'] ?? ''),
                (string) ($probe['tenant'] ?? ''), $generation, (string) ($probe['connection'] ?? ''),
                (string) ($probe['transaction'] ?? ''), (string) ($probe['operation'] ?? ''),
                (string) ($probe['target'] ?? ''), isset($probe['value']) ? (string) $probe['value'] : null,
                isset($probe['bind_connection']) ? (string) $probe['bind_connection'] : null,
                isset($probe['bind_transaction']) ? (string) $probe['bind_transaction'] : null,
            );
        }

        if ($this->transport->state() !== ['transaction' => null, 'bound' => null]) {
            throw new LogicException('offline-f3-cleanup-incomplete');
        }
        if (($environment['evidence_terminal'] ?? null) !== 'COMPLETE' || ($environment['role_cleanup'] ?? false) !== true || ($environment['container_stopped'] ?? false) !== true) {
            throw new LogicException('offline-f3-terminal-invalid');
        }

        return [
            'classification' => 'OFFLINE_SIMULATION_NOT_RUNTIME',
            'f3_classification' => 'F3_CONTRACT_VERIFIED_BY_ADAPTER',
            'records' => $records,
            'terminal' => 'COMPLETE',
        ];
    }

    /** @param array<string,mixed> $environment */
    private function assertEnvironment(array $environment): void
    {
        $required = [
            'run_id' => static fn ($value): bool => $value === 'offline-f3-run',
            'task_owned' => static fn ($value): bool => $value === true,
            'container_id' => static fn ($value): bool => is_string($value) && preg_match('/^[a-f0-9]{64}$/', $value) === 1,
            'container_name' => static fn ($value): bool => $value === 'dcrm-p1p2-ownerchain-offline-008-pg',
            'database' => static fn ($value): bool => $value === 'dcrm_p1p2_offline_008',
            'system_identifier' => static fn ($value): bool => $value === '7705999999999999008',
            'published_ports' => static fn ($value): bool => $value === 0,
            'migration_ledger' => static fn ($value): bool => $value === true,
            'force_rls' => static fn ($value): bool => $value === true,
            'restricted_grant_denied' => static fn ($value): bool => $value === true,
            'restricted_principal' => static fn ($value): bool => $value === 'dl_core_truntime',
            'membership_active' => static fn ($value): bool => $value === true,
            'evidence_nonce' => static fn ($value): bool => is_string($value) && $value !== '',
            'capture_state' => static fn ($value): bool => $value === 'CAPTURED',
            'timeout_state' => static fn ($value): bool => $value === 'WITHIN_BOUND',
            'cancelled' => static fn ($value): bool => $value === false,
        ];
        foreach ($required as $key => $valid) {
            if (! $valid($environment[$key] ?? null)) {
                throw new LogicException('offline-f3-guard-' . $key);
            }
        }
    }
}
