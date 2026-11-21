<?php

namespace App\Modules\Tenancy\Domain;

use RuntimeException;

final class AuthorizationDeniedException extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('AUTHORIZATION_DENIED');
    }
}
