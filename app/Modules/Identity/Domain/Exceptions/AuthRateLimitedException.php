<?php

namespace App\Modules\Identity\Domain\Exceptions;

use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

final class AuthRateLimitedException extends TooManyRequestsHttpException
{
    public function __construct(int $retryAfter = 60)
    {
        parent::__construct($retryAfter, 'Too many authentication requests.');
    }
}
