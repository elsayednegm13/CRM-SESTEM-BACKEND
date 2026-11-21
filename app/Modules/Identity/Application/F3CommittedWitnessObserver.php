<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\Request;

interface F3CommittedWitnessObserver
{
    /** @return array<string,mixed> */
    public function observe(
        TenantHostContext $host,
        string $email,
        string $password,
        string $retryKey,
        Request $request,
        string $actorTenantId,
        string $observerMembershipId,
        string $adminMembershipId,
        string $ownWitnessId,
        string $foreignTenantId,
        string $foreignWitnessId,
        string $commitXid,
        int $fixtureBackendPid,
        string $runId,
    ): array;
}
