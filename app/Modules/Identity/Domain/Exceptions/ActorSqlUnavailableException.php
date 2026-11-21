<?php

namespace App\Modules\Identity\Domain\Exceptions;

use RuntimeException;

final class ActorSqlUnavailableException extends RuntimeException
{
    private function __construct(public readonly string $reason)
    {
        parent::__construct('Actor SQL service is unavailable.');
    }

    public static function missingCredential(): self
    {
        return new self('MISSING_CREDENTIAL');
    }

    public static function unmappedActor(): self
    {
        return new self('UNMAPPED_ACTOR');
    }

    public static function identityMismatch(): self
    {
        return new self('IDENTITY_MISMATCH');
    }

    public static function missingFunction(): self
    {
        return new self('MISSING_FUNCTION');
    }
}
