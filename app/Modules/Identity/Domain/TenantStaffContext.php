<?php

namespace App\Modules\Identity\Domain;

final readonly class TenantStaffContext
{
    public function __construct(
        public string $tenantId,
        public string $hostname,
        public string $userId,
        public string $membershipId,
        public int $authVersion,
        public int $authorizationVersion,
    ) {
    }
}
