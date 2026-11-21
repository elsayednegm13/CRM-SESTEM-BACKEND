<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\ActiveMembershipLookup;
use App\Modules\Tenancy\Infrastructure\Persistence\RlsDatabaseContext;
use Illuminate\Support\Facades\DB;

final class ResolveTenantContext
{
    public function __construct(
        private readonly TenantSecurityEvents $events,
        private readonly ActiveMembershipLookup $memberships,
        private readonly RlsDatabaseContext $dbContext,
    )
    {
    }

    public function resolve(string $userId, int $identityAuthVersion, string $requestId): TenantContext
    {
        return $this->dbContext->discoverForUser($userId, function (RlsDatabaseContext $dbContext) use ($userId, $identityAuthVersion, $requestId): TenantContext {
            $memberships = $this->memberships->forUser($userId);

            if ($memberships->isEmpty()) {
                $this->events->emit('TenantMembershipMissing', 'denied', $requestId, $userId);
                throw TenantAccessException::membershipRequired();
            }
            if ($memberships->count() !== 1) {
                $this->events->emit('TenantMembershipIntegrityViolation', 'denied', $requestId, $userId);
                throw TenantAccessException::integrity();
            }

            $membership = $memberships->first();
            $tenantId = $dbContext->activateFromMembership($userId, $membership->id);
            $tenant = DB::table('tenants')->where('id', $tenantId)->first(['id', 'status']);
            if (! $tenant || $tenant->status !== 'ACTIVE') {
                $this->events->emit('TenantUnavailable', 'denied', $requestId, $userId, $tenantId, $membership->id);
                throw TenantAccessException::unavailable();
            }

            $context = new TenantContext(
                $userId,
                $tenant->id,
                $membership->id,
                (int) $membership->authorization_version,
                $identityAuthVersion,
                $requestId,
            );
            $this->events->emit('TenantContextResolved', 'allowed', $requestId, $userId, $tenant->id, $membership->id);

            return $context;
        });
    }
}
