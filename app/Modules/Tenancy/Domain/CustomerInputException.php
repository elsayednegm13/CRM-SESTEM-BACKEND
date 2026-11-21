<?php

declare(strict_types=1);

namespace App\Modules\Tenancy\Domain;

use RuntimeException;

/** Framework-free domain validation used before database work starts. */
final class CustomerInputException extends RuntimeException
{
    /** @param array<string,list<string>> $errors */
    public function __construct(public readonly array $errors)
    {
        parent::__construct('Customer input is invalid.');
    }
}
