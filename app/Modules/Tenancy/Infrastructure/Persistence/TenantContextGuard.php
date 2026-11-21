<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\TenantContext;
use Closure;
use Illuminate\Support\Facades\DB;

/** Revalidates a grant inside the same transaction as tenant-owned data access. */
final class TenantContextGuard
{
    public function __construct(private readonly RlsDatabaseContext $dbContext)
    {
    }

    public function run(?TenantContext $context, Closure $operation, bool $write = false): mixed
    {
        if (! $context || $context->mode !== TenantContext::MODE) {
            throw TenantAccessException::contextRequired();
        }

        return $this->dbContext->forTenant($context, function () use ($context, $operation, $write): mixed {
            // Tenant row first: every 07B grant/status mutation uses this same lock order.
            $tenantQuery = DB::table('tenants')->where('id', $context->tenantId);
            $tenant = ($write ? $tenantQuery->lockForUpdate() : $tenantQuery->sharedLock())
                ->first(['status']);
            if (! $tenant || $tenant->status !== 'ACTIVE') {
                throw TenantAccessException::unavailable();
            }

            // Identity is re-read on every protected request, but tenant work does
            // not lock the global identity row. A concurrent disable may allow an
            // already-validated in-flight transaction to finish; the next request
            // observes DISABLED / the incremented auth_version and is denied.
            $user = DB::table('users')->where('id', $context->userId)
                ->first(['status', 'auth_version']);
            if (! $user || $user->status !== 'ACTIVE' || (int) $user->auth_version !== $context->identityAuthVersion) {
                throw TenantAccessException::contextRequired();
            }

            $membershipQuery = DB::table('tenant_memberships')->where('id', $context->membershipId)
                ->where('user_id', $context->userId)->where('tenant_id', $context->tenantId);
            $membership = ($write ? $membershipQuery->lockForUpdate() : $membershipQuery->sharedLock())
                ->first(['status', 'authorization_version']);
            if (! $membership || $membership->status !== 'ACTIVE'
                || (int) $membership->authorization_version !== $context->membershipAuthorizationVersion) {
                throw TenantAccessException::contextRequired();
            }

            return $operation();
        });
    }
}
