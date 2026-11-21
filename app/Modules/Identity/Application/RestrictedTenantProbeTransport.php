<?php
declare(strict_types=1);
namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantStaffContext;

/** Future runtime adapters must use the already-bound application transaction. */
interface RestrictedTenantProbeTransport
{
    /** Must bind and attest the active application transaction before returning a scope. */
    public function beginBound(TenantStaffContext $context, string $authorityGeneration, RestrictedTenantProbePlan $plan): RestrictedTenantProbeScope;
}
