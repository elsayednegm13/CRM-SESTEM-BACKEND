<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\TenantContext;
use Illuminate\Support\Facades\Log;

final class AuthorizationSecurityEvents
{
    public function emit(string $event, string $result, TenantContext $context, ?string $targetId = null): void
    {
        Log::channel('structured')->info('tenant.authorization', array_filter([
            'event' => $event,
            'result' => $result,
            'request_id' => $context->requestId,
            'user_id' => $context->userId,
            'tenant_id' => $context->tenantId,
            'membership_id' => $context->membershipId,
            'target_id' => $targetId,
            'timestamp' => now()->toIso8601String(),
        ], static fn ($value) => $value !== null));
    }
}
