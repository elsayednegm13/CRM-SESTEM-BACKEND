<?php
declare(strict_types=1);
namespace App\Modules\Identity\Application;
interface RestrictedTenantProbeScope { /** @return array{outcome:string,row_effects:int} */ public function execute(): array; public function close(): void; }
