<?php

namespace App\Modules\Tenancy\Application;

use Illuminate\Support\Facades\Log;

final class TenantSecurityEvents
{
    public function emit(string $event, string $result, string $requestId, string $userId, ?string $tenantId = null, ?string $membershipId = null): void
    {
        $context = array_filter([
            'event' => $event,
            'result' => $result,
            'request_id' => $requestId,
            'user_id' => $userId,
            'tenant_id' => $tenantId,
            'membership_id' => $membershipId,
            'timestamp' => now()->toIso8601String(),
        ], static fn ($value) => $value !== null);

        Log::channel('structured')->info('tenant.security', $context);
    }
}
