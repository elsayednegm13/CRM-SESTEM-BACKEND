<?php
declare(strict_types=1);
namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\Request;
use LogicException;

/** Acceptance-only composition; deliberately not registered as a web route or container binding. */
final class TenantRestrictedProbeCoordinator
{
    public function __construct(
        private readonly ?TenantAuthorityBridge $bridge,
        private readonly ?RestrictedTenantProbeTransport $transport,
        private readonly ?LaravelRestrictedTenantRuntimeAdapter $runtimeAdapter = null,
    ) {}

    public static function forRuntimeAdapter(LaravelRestrictedTenantRuntimeAdapter $adapter): self
    {
        return new self(null, null, $adapter);
    }
    /** @return array{outcome:string,row_effects:int} */
    public function authenticateAndExecute(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request, RestrictedTenantProbePlan $plan): array
    {
        if ($this->bridge === null || $this->transport === null) {
            throw new LogicException('Offline restricted tenant probe transport is unavailable.');
        }
        $authority = $this->bridge->authenticateAndBind($host, $email, $password, $retryKey, $request);
        if ($authority['context']->tenantId !== $plan->actorTenantId) {
            throw new LogicException('Restricted tenant probe actor/tenant mismatch.');
        }
        $scope = $this->transport->beginBound($authority['context'], $authority['authority_generation'], $plan);
        try { return $scope->execute(); } finally { $scope->close(); }
    }

    /** @return array<string,mixed> */
    public function authenticateAndExecuteRuntime(TenantHostContext $host, string $email, string $password, string $retryKey, Request $request, RestrictedTenantProbePlan $plan): array
    {
        if ($this->runtimeAdapter === null) {
            throw new LogicException('Real restricted tenant runtime adapter is unavailable.');
        }

        return $this->runtimeAdapter->authenticateAndExecute($host, $email, $password, $retryKey, $request, $plan);
    }
}
