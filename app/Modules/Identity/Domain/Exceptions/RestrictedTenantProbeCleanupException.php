<?php

declare(strict_types=1);

namespace App\Modules\Identity\Domain\Exceptions;

use RuntimeException;
use Throwable;

final class RestrictedTenantProbeCleanupException extends RuntimeException
{
    public function __construct(public readonly string $primaryType, public readonly Throwable $cleanup, Throwable $primary)
    {
        parent::__construct('Restricted tenant probe failed and cleanup also failed.', 0, $primary);
    }

    public function cleanupType(): string
    {
        return $this->cleanup::class;
    }
}
