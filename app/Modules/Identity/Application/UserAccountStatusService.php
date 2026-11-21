<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Enums\UserStatus;
use App\Modules\Identity\Infrastructure\Persistence\User;
use App\Modules\Tenancy\Application\TenantAdminInvariant;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Infrastructure\Persistence\RlsDatabaseContext;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Support\Facades\DB;

final class UserAccountStatusService
{
    public function __construct(
        private readonly TenantAdminInvariant $adminInvariant,
        private readonly RlsDatabaseContext $dbContext,
        private readonly SecurityAuditWriter $audit,
    ) {}

    public function disable(User $user): User
    {
        $userId = (string) $user->getKey();
        return $this->dbContext->discoverForUser($userId, function (RlsDatabaseContext $dbContext) use ($user, $userId): User {
            $memberships = DB::table('tenant_memberships')->where('user_id', $userId)
                ->where('status', 'ACTIVE')->limit(2)->get(['id', 'tenant_id']);
            if ($memberships->count() > 1) {
                throw new AuthorizationDeniedException;
            }
            $tenantId = $memberships->first()?->tenant_id;
            if ($tenantId !== null) {
                $dbContext->activateFromMembership($userId, $memberships->first()->id);
                DB::table('tenants')->where('id', $tenantId)->lockForUpdate()->firstOrFail(['id']);
            }
            $current = User::query()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $currentTenantId = DB::table('tenant_memberships')->where('user_id', $current->getKey())
                ->where('status', 'ACTIVE')->value('tenant_id');
            if ($currentTenantId !== $tenantId) {
                throw new AuthorizationDeniedException;
            }
            if ($current->status !== UserStatus::DISABLED) {
                $current->forceFill([
                    'status' => UserStatus::DISABLED,
                    'auth_version' => $current->auth_version + 1,
                ])->save();
                if ($tenantId !== null) {
                    $this->adminInvariant->assertRemains($tenantId);
                }
                $this->audit->appendInternalUserDisabled($userId, $tenantId);
            }

            return $current->refresh();
        });
    }
}
