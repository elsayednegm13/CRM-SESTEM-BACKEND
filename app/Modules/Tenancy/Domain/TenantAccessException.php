<?php

namespace App\Modules\Tenancy\Domain;

use RuntimeException;

final class TenantAccessException extends RuntimeException
{
    private function __construct(public readonly string $safeCode, public readonly int $status)
    {
        parent::__construct($safeCode);
    }

    public static function membershipRequired(): self
    {
        return new self('TENANT_MEMBERSHIP_REQUIRED', 403);
    }

    public static function integrity(): self
    {
        return new self('TENANT_CONTEXT_INTEGRITY_ERROR', 403);
    }

    public static function unavailable(): self
    {
        return new self('TENANT_UNAVAILABLE', 403);
    }

    public static function contextRequired(): self
    {
        return new self('TENANT_CONTEXT_REQUIRED', 403);
    }

    public static function selectorNotAllowed(): self
    {
        return new self('TENANT_SELECTOR_NOT_ALLOWED', 400);
    }

    public static function objectNotFound(): self
    {
        return new self('RESOURCE_NOT_FOUND', 404);
    }
}
