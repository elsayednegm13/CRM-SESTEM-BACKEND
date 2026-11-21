<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Database\Connection;

interface RestrictedTenantProbeExecutor
{
    /** @return array{attempted:bool,executed:bool,observed_outcome:string,row_effects:int,postcondition_proved:bool} */
    public function execute(Connection $connection, TenantStaffContext $context, RestrictedTenantProbePlan $plan): array;
}
