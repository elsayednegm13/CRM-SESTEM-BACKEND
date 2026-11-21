<?php

namespace App\Modules\Identity\Domain;

final readonly class TenantHostContext
{
    public function __construct(
        public string $tenantId,
        public string $tenantSlug,
        public string $hostname,
        public string $baseDomain,
        public string $environmentScope,
    ) {
    }
}
