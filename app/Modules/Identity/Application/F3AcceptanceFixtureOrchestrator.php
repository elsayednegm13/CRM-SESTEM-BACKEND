<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

interface F3AcceptanceFixtureOrchestrator
{
    /** @param array<string,mixed> $input @return array<string,mixed> */
    public function prepare(array $input): array;
}
