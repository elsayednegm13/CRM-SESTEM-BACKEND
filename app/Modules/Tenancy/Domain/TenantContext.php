<?php

namespace App\Modules\Tenancy\Domain;

final readonly class TenantContext
{
    public const MODE = 'TENANT';

    public function __construct(
        public string $userId,
        public string $tenantId,
        public string $membershipId,
        public int $membershipAuthorizationVersion,
        public int $identityAuthVersion,
        public string $requestId,
        public string $mode = self::MODE,
    ) {
    }
}
