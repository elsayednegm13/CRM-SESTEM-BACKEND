<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

interface F3AcceptanceFixturePrewriteAttestor
{
    /** Fail closed before any bootstrap, provisioning, tenant, or Lead write. */
    public function attest(string $runId, string $permitId): void;
}
