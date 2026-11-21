<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\Role;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** All ordinary mutations hold the tenant-first write guard through final invariant check. */
final class TenantRoleMutationService
{
    public function __construct(
        private readonly TenantAuthorizationService $authorization,
        private readonly AuthorizationSecurityEvents $events,
        private readonly TenantAdminInvariant $adminInvariant,
        private readonly SecurityAuditWriter $audit,
    ) {
    }

    public function createRole(TenantContext $actor, string $name): string
    {
        $id = $this->authorization->runWithCapability($actor, 'role.manage', function () use ($actor, $name): string {
            $normalized = Str::slug($name, '_');
            if (! preg_match('/^[a-z][a-z0-9_]*$/', $normalized)) {
                throw new AuthorizationDeniedException;
            }
            $role = Role::query()->create([
                'tenant_id' => $actor->tenantId,
                'display_name' => $name,
                'normalized_name' => $normalized,
            ]);
            $this->audit->appendTenantMutation($actor, AuditEventType::ROLE_CREATED, $role->id);
            return $role->id;
        }, true);
        $this->events->emit('RoleCreated', 'allowed', $actor, $id);
        return $id;
    }

    /** @param array<int, array{permission:string, scope:?string}> $grants */
    public function updateRoleGrants(TenantContext $actor, string $roleId, array $grants): void
    {
        $this->authorization->runWithCapability($actor, 'role.manage', function (array $snapshot) use ($actor, $roleId, $grants): void {
            $role = $this->roleForUpdate($actor, $roleId);
            $this->denyOwnRoleEdit($actor, $roleId);
            $seen = [];
            foreach ($grants as $grant) {
                $key = $grant['permission'] ?? null;
                $scope = $grant['scope'] ?? null;
                if (! is_string($key) || ! (is_string($scope) || $scope === null)
                    || isset($seen[$key]) || ! $this->authorization->canDelegateWithinGuard($snapshot, $key, $scope)) {
                    throw new AuthorizationDeniedException;
                }
                $seen[$key] = true;
            }
            DB::table('role_permissions')->where('tenant_id', $actor->tenantId)->where('role_id', $roleId)->delete();
            foreach ($grants as $grant) {
                DB::table('role_permissions')->insert([
                    'tenant_id' => $actor->tenantId, 'role_id' => $roleId,
                    'permission_key' => $grant['permission'], 'scope' => $grant['scope'] ?? null,
                ]);
            }
            DB::table('roles')->where('id', $role->id)->increment('version', 1, ['updated_at' => now()]);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->appendTenantMutation($actor, AuditEventType::ROLE_GRANTS_CHANGED, $roleId);
        }, true);
        $this->events->emit('RoleGrantsChanged', 'allowed', $actor, $roleId);
    }

    public function archiveRole(TenantContext $actor, string $roleId): void
    {
        $this->authorization->runWithCapability($actor, 'role.manage', function () use ($actor, $roleId): void {
            $this->roleForUpdate($actor, $roleId);
            $this->denyOwnRoleEdit($actor, $roleId);
            DB::table('roles')->where('tenant_id', $actor->tenantId)->where('id', $roleId)
                ->update(['status' => 'ARCHIVED', 'archived_at' => now(), 'updated_at' => now(), 'version' => DB::raw('version + 1')]);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->appendTenantMutation($actor, AuditEventType::ROLE_ARCHIVED, $roleId);
        }, true);
        $this->events->emit('RoleArchived', 'allowed', $actor, $roleId);
    }

    public function assignRole(TenantContext $actor, string $targetMembershipId, string $roleId): void
    {
        try {
            $this->authorization->runWithCapability($actor, 'member.manage', function (array $snapshot) use ($actor, $targetMembershipId, $roleId): void {
                $this->targetMembershipForUpdate($actor, $targetMembershipId, true);
                $role = $this->roleForUpdate($actor, $roleId);
                $grants = DB::table('role_permissions')->where('tenant_id', $actor->tenantId)
                    ->where('role_id', $role->id)->get(['permission_key', 'scope']);
                foreach ($grants as $grant) {
                    if (! $this->authorization->canDelegateWithinGuard($snapshot, $grant->permission_key, $grant->scope)) {
                        throw new AuthorizationDeniedException;
                    }
                }
                DB::table('membership_roles')->insert([
                    'tenant_id' => $actor->tenantId, 'membership_id' => $targetMembershipId,
                    'role_id' => $roleId, 'assigned_by_user_id' => $actor->userId, 'assigned_at' => now(),
                ]);
                $this->incrementMembershipVersion($actor, $targetMembershipId);
                $this->assertEffectiveAdminRemains($actor);
                $this->audit->appendTenantMutation($actor, AuditEventType::ROLE_ASSIGNED, $targetMembershipId);
            }, true);
        } catch (QueryException $exception) {
            if (($exception->errorInfo[0] ?? null) === '23505') {
                throw new AuthorizationDeniedException;
            }
            throw $exception;
        }
        $this->events->emit('RoleAssigned', 'allowed', $actor, $targetMembershipId);
    }

    public function revokeRole(TenantContext $actor, string $targetMembershipId, string $roleId): void
    {
        $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId, $roleId): void {
            $this->targetMembershipForUpdate($actor, $targetMembershipId, false);
            $this->roleForUpdate($actor, $roleId);
            $deleted = DB::table('membership_roles')->where('tenant_id', $actor->tenantId)
                ->where('membership_id', $targetMembershipId)->where('role_id', $roleId)->delete();
            if ($deleted !== 1) {
                throw new AuthorizationDeniedException;
            }
            $this->incrementMembershipVersion($actor, $targetMembershipId);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->appendTenantMutation($actor, AuditEventType::ROLE_REVOKED, $targetMembershipId);
        }, true);
        $this->events->emit('RoleRevoked', 'allowed', $actor, $targetMembershipId);
    }

    public function suspendMembership(TenantContext $actor, string $targetMembershipId): void
    {
        $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId): void {
            $membership = $this->targetMembershipForUpdate($actor, $targetMembershipId, true);
            if ($membership->status !== 'ACTIVE') {
                throw new AuthorizationDeniedException;
            }
            DB::table('tenant_memberships')->where('id', $targetMembershipId)
                ->update(['status' => 'SUSPENDED', 'updated_at' => now(), 'authorization_version' => DB::raw('authorization_version + 1')]);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->appendTenantMutation($actor, AuditEventType::MEMBERSHIP_SUSPENDED, $targetMembershipId);
        }, true);
        $this->events->emit('MembershipAuthorizationChanged', 'allowed', $actor, $targetMembershipId);
    }

    public function reactivateMembership(TenantContext $actor, string $targetMembershipId): void
    {
        try {
            $this->authorization->runWithCapability($actor, 'member.manage', function (array $snapshot) use ($actor, $targetMembershipId): void {
                $membership = $this->targetMembershipForUpdate($actor, $targetMembershipId, false);
                if ($membership->status !== 'SUSPENDED' || $this->membershipHasAdminGrant($actor, $targetMembershipId)) {
                    throw new AuthorizationDeniedException;
                }
                $targetUser = DB::table('users')->where('id', DB::table('tenant_memberships')
                    ->where('id', $targetMembershipId)->value('user_id'))->first(['status']);
                if (! $targetUser || $targetUser->status !== 'ACTIVE') {
                    throw new AuthorizationDeniedException;
                }
                $grants = DB::table('membership_roles as mr')
                    ->join('roles as r', function ($join): void {
                        $join->on('r.tenant_id', '=', 'mr.tenant_id')->on('r.id', '=', 'mr.role_id');
                    })
                    ->join('role_permissions as rp', function ($join): void {
                        $join->on('rp.tenant_id', '=', 'mr.tenant_id')->on('rp.role_id', '=', 'mr.role_id');
                    })
                    ->where('mr.tenant_id', $actor->tenantId)->where('mr.membership_id', $targetMembershipId)
                    ->where('r.status', 'ACTIVE')->get(['rp.permission_key', 'rp.scope']);
                foreach ($grants as $grant) {
                    if (! $this->authorization->canDelegateWithinGuard($snapshot, $grant->permission_key, $grant->scope)) {
                        throw new AuthorizationDeniedException;
                    }
                }
                DB::table('tenant_memberships')->where('id', $targetMembershipId)
                    ->update(['status' => 'ACTIVE', 'updated_at' => now(), 'authorization_version' => DB::raw('authorization_version + 1')]);
                $this->assertEffectiveAdminRemains($actor);
                $this->audit->appendTenantMutation($actor, AuditEventType::MEMBERSHIP_REACTIVATED, $targetMembershipId);
            }, true);
        } catch (QueryException $exception) {
            if (($exception->errorInfo[0] ?? null) === '23505') {
                throw new AuthorizationDeniedException;
            }
            throw $exception;
        }
        $this->events->emit('MembershipAuthorizationChanged', 'allowed', $actor, $targetMembershipId);
    }

    private function targetMembershipForUpdate(TenantContext $actor, string $id, bool $mustBeActive): object
    {
        if ($id === $actor->membershipId) {
            throw new AuthorizationDeniedException;
        }
        $membership = DB::table('tenant_memberships')->where('tenant_id', $actor->tenantId)
            ->where('id', $id)->lockForUpdate()->first(['id', 'status']);
        if (! $membership || ($mustBeActive && $membership->status !== 'ACTIVE')) {
            throw new AuthorizationDeniedException;
        }
        return $membership;
    }

    private function roleForUpdate(TenantContext $actor, string $id): object
    {
        $role = DB::table('roles')->where('tenant_id', $actor->tenantId)->where('id', $id)
            ->lockForUpdate()->first(['id', 'status']);
        if (! $role || $role->status !== 'ACTIVE') {
            throw new AuthorizationDeniedException;
        }
        return $role;
    }

    private function denyOwnRoleEdit(TenantContext $actor, string $roleId): void
    {
        if (DB::table('membership_roles')->where('tenant_id', $actor->tenantId)
            ->where('membership_id', $actor->membershipId)->where('role_id', $roleId)->exists()) {
            throw new AuthorizationDeniedException;
        }
    }

    private function incrementMembershipVersion(TenantContext $actor, string $id): void
    {
        DB::table('tenant_memberships')->where('tenant_id', $actor->tenantId)->where('id', $id)
            ->increment('authorization_version', 1, ['updated_at' => now()]);
    }

    private function membershipHasAdminGrant(TenantContext $actor, string $id): bool
    {
        return DB::table('membership_roles as mr')
            ->join('roles as r', function ($join): void {
                $join->on('r.tenant_id', '=', 'mr.tenant_id')->on('r.id', '=', 'mr.role_id');
            })
            ->join('role_permissions as rp', function ($join): void {
                $join->on('rp.tenant_id', '=', 'mr.tenant_id')->on('rp.role_id', '=', 'mr.role_id');
            })
            ->where('mr.tenant_id', $actor->tenantId)->where('mr.membership_id', $id)
            ->where('r.status', 'ACTIVE')->where('rp.permission_key', 'company.administer')
            ->where('rp.scope', 'ALL_TENANT')->exists();
    }

    private function assertEffectiveAdminRemains(TenantContext $actor): void
    {
        try {
            $this->adminInvariant->assertRemains($actor->tenantId);
        } catch (AuthorizationDeniedException $exception) {
            $this->events->emit('LastAdminMutationDenied', 'denied', $actor);
            throw $exception;
        }
    }
}
