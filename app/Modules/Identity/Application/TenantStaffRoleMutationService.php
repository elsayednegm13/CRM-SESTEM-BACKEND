<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\ActorSqlUnavailableException;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Shared\Audit\TenantStaffAuditWriter;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Tenant-staff analogue of App\Modules\Tenancy\Application\TenantRoleMutationService, operating
 * on tenant_staff_membership_roles/tenant_staff_permission_grants instead of the legacy
 * membership_roles table. Every write uses the pgsql_tenant_runtime connection explicitly --
 * that is the connection TenantStaffRequestContext middleware already opened a transaction on
 * and set the TENANT-mode GUCs for, for the whole request. The default connection has neither.
 */
final class TenantStaffRoleMutationService
{
    private const CONNECTION = 'pgsql_tenant_runtime';

    public function __construct(
        private readonly TenantStaffAuthorizationService $authorization,
        private readonly TenantStaffAdminInvariant $adminInvariant,
        private readonly TenantStaffAuditWriter $audit,
    ) {}

    public function createRole(TenantStaffContext $actor, string $name): string
    {
        return $this->authorization->runWithCapability($actor, 'role.manage', function () use ($name, $actor): string {
            $normalized = Str::slug($name, '_');
            if (! preg_match('/^[a-z][a-z0-9_]*$/', $normalized)) {
                throw new AuthorizationDeniedException;
            }
            $id = (string) Str::uuid7();
            DB::connection(self::CONNECTION)->table('roles')->insert([
                'id' => $id, 'tenant_id' => $actor->tenantId,
                'display_name' => $name, 'normalized_name' => $normalized,
                'created_at' => now(), 'updated_at' => now(),
            ]);
            $this->audit->appendForRole($actor, 'tenant_staff.role_created', $id);
            return $id;
        });
    }

    /** @param array<int, array{permission:string, scope:?string}> $grants */
    public function updateRoleGrants(TenantStaffContext $actor, string $roleId, array $grants): void
    {
        $this->authorization->runWithCapability($actor, 'role.manage', function (array $actorGrants) use ($actor, $roleId, $grants): void {
            $connection = DB::connection(self::CONNECTION);
            $role = $this->roleForUpdate($actor, $roleId);
            $this->denyOwnRoleEdit($actor, $roleId);
            $seen = [];
            foreach ($grants as $grant) {
                $key = $grant['permission'] ?? null;
                $scope = $grant['scope'] ?? null;
                if (! is_string($key) || ! (is_string($scope) || $scope === null)
                    || isset($seen[$key]) || ! $this->authorization->canDelegate($actorGrants, $key, $scope)) {
                    throw new AuthorizationDeniedException;
                }
                $seen[$key] = true;
            }
            $connection->table('role_permissions')->where('tenant_id', $actor->tenantId)->where('role_id', $roleId)->delete();
            foreach ($grants as $grant) {
                $connection->table('role_permissions')->insert([
                    'tenant_id' => $actor->tenantId, 'role_id' => $roleId,
                    'permission_key' => $grant['permission'], 'scope' => $grant['scope'] ?? null,
                ]);
            }
            $connection->table('roles')->where('tenant_id', $actor->tenantId)->where('id', $role->id)
                ->update(['version' => $role->version + 1, 'updated_at' => now()]);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->appendForRole($actor, 'tenant_staff.role_grants_changed', $roleId);
        });
    }

    public function archiveRole(TenantStaffContext $actor, string $roleId): void
    {
        $this->authorization->runWithCapability($actor, 'role.manage', function () use ($actor, $roleId): void {
            $role = $this->roleForUpdate($actor, $roleId);
            $this->denyOwnRoleEdit($actor, $roleId);
            DB::connection(self::CONNECTION)->table('roles')->where('tenant_id', $actor->tenantId)->where('id', $roleId)
                ->update(['status' => 'ARCHIVED', 'archived_at' => now(), 'updated_at' => now(), 'version' => $role->version + 1]);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->appendForRole($actor, 'tenant_staff.role_archived', $roleId);
        });
    }

    public function assignRole(TenantStaffContext $actor, string $targetMembershipId, string $roleId): void
    {
        try {
            $this->authorization->runWithCapability($actor, 'member.manage', function (array $actorGrants) use ($actor, $targetMembershipId, $roleId): void {
                $connection = DB::connection(self::CONNECTION);
                $this->targetMembershipForUpdate($actor, $targetMembershipId, true);
                $role = $this->roleForUpdate($actor, $roleId);
                $roleGrants = $connection->table('role_permissions')->where('tenant_id', $actor->tenantId)
                    ->where('role_id', $role->id)->get(['permission_key', 'scope']);
                foreach ($roleGrants as $grant) {
                    if (! $this->authorization->canDelegate($actorGrants, $grant->permission_key, $grant->scope)) {
                        throw new AuthorizationDeniedException;
                    }
                }
                $connection->table('tenant_staff_membership_roles')->insert([
                    'id' => (string) Str::uuid7(), 'tenant_id' => $actor->tenantId,
                    'membership_id' => $targetMembershipId, 'role_id' => $roleId,
                    'assigned_by_membership_id' => $actor->membershipId,
                    'assigned_at' => now(), 'created_at' => now(), 'updated_at' => now(),
                ]);
                $this->incrementMembershipVersion($actor, $targetMembershipId);
                $this->assertEffectiveAdminRemains($actor);
                $this->audit->append($actor, 'tenant_staff.role_assigned', $this->staffUserFor($actor, $targetMembershipId));
            });
        } catch (QueryException $exception) {
            if (($exception->errorInfo[0] ?? null) === '23505') {
                throw new AuthorizationDeniedException;
            }
            throw $exception;
        }
    }

    public function revokeRole(TenantStaffContext $actor, string $targetMembershipId, string $roleId): void
    {
        $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId, $roleId): void {
            $connection = DB::connection(self::CONNECTION);
            $this->targetMembershipForUpdate($actor, $targetMembershipId, false);
            $this->roleForUpdate($actor, $roleId);
            $updated = $connection->table('tenant_staff_membership_roles')
                ->where('tenant_id', $actor->tenantId)->where('membership_id', $targetMembershipId)
                ->where('role_id', $roleId)->whereNull('revoked_at')
                ->update(['revoked_at' => now(), 'revoked_by_membership_id' => $actor->membershipId, 'updated_at' => now()]);
            if ($updated !== 1) {
                throw new AuthorizationDeniedException;
            }
            $this->incrementMembershipVersion($actor, $targetMembershipId);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->append($actor, 'tenant_staff.role_revoked', $this->staffUserFor($actor, $targetMembershipId));
        });
    }

    public function grantPermission(TenantStaffContext $actor, string $targetMembershipId, string $permission, ?string $scope): void
    {
        if ((bool) config('f06_actor_sql.enabled')
            && in_array(app()->environment(), (array) config('f06_actor_sql.allow_env', []), true)) {
            $this->authorization->runWithCapability($actor, 'member.manage', function (array $actorGrants) use ($actor, $targetMembershipId, $permission, $scope): void {
                if ($targetMembershipId === $actor->membershipId
                    || ! $this->authorization->canDelegate($actorGrants, $permission, $scope)) {
                    throw new AuthorizationDeniedException;
                }
                try {
                    DB::connection(self::CONNECTION)->selectOne(
                        'SELECT public.f06team01_direct_permission(?, ?, ?, ?, ?, ?) AS version',
                        ['GRANT', $targetMembershipId, $permission, $scope, (string) Str::uuid7(), (string) Str::uuid7()],
                    );
                } catch (QueryException $exception) {
                    if (($exception->errorInfo[0] ?? $exception->getCode()) === '42883') {
                        throw ActorSqlUnavailableException::missingFunction();
                    }
                    if (in_array($exception->errorInfo[0] ?? null, ['23505', '42501'], true)) {
                        throw new AuthorizationDeniedException;
                    }
                    throw $exception;
                }
                $this->assertEffectiveAdminRemains($actor);
            });
            return;
        }
        $this->authorization->runWithCapability($actor, 'member.manage', function (array $actorGrants) use ($actor, $targetMembershipId, $permission, $scope): void {
            $this->targetMembershipForUpdate($actor, $targetMembershipId, true);
            if (! $this->authorization->canDelegate($actorGrants, $permission, $scope)) {
                throw new AuthorizationDeniedException;
            }
            try {
                DB::connection(self::CONNECTION)->table('tenant_staff_permission_grants')->insert([
                    'id' => (string) Str::uuid7(), 'tenant_id' => $actor->tenantId,
                    'membership_id' => $targetMembershipId, 'permission_key' => $permission, 'scope' => $scope,
                    'granted_by_membership_id' => $actor->membershipId, 'granted_at' => now(),
                    'created_at' => now(), 'updated_at' => now(),
                ]);
            } catch (QueryException $exception) {
                if (($exception->errorInfo[0] ?? null) === '23505') {
                    throw new AuthorizationDeniedException;
                }
                throw $exception;
            }
            $this->incrementMembershipVersion($actor, $targetMembershipId);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->append($actor, 'tenant_staff.permission_granted', $this->staffUserFor($actor, $targetMembershipId));
        });
    }

    public function revokePermission(TenantStaffContext $actor, string $targetMembershipId, string $permission, ?string $scope): void
    {
        if ((bool) config('f06_actor_sql.enabled')
            && in_array(app()->environment(), (array) config('f06_actor_sql.allow_env', []), true)) {
            $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId, $permission, $scope): void {
                if ($targetMembershipId === $actor->membershipId) {
                    throw new AuthorizationDeniedException;
                }
                try {
                    DB::connection(self::CONNECTION)->selectOne(
                        'SELECT public.f06team01_direct_permission(?, ?, ?, ?, ?, ?) AS version',
                        ['REVOKE', $targetMembershipId, $permission, $scope, (string) Str::uuid7(), (string) Str::uuid7()],
                    );
                } catch (QueryException $exception) {
                    if (($exception->errorInfo[0] ?? $exception->getCode()) === '42883') {
                        throw ActorSqlUnavailableException::missingFunction();
                    }
                    if (($exception->errorInfo[0] ?? null) === '42501') {
                        throw new AuthorizationDeniedException;
                    }
                    throw $exception;
                }
                $this->assertEffectiveAdminRemains($actor);
            });
            return;
        }
        $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId, $permission, $scope): void {
            $this->targetMembershipForUpdate($actor, $targetMembershipId, false);
            $query = DB::connection(self::CONNECTION)->table('tenant_staff_permission_grants')
                ->where('tenant_id', $actor->tenantId)->where('membership_id', $targetMembershipId)
                ->where('permission_key', $permission)->whereNull('revoked_at');
            $scope === null ? $query->whereNull('scope') : $query->where('scope', $scope);
            $updated = $query->update(['revoked_at' => now(), 'revoked_by_membership_id' => $actor->membershipId, 'updated_at' => now()]);
            if ($updated !== 1) {
                throw new AuthorizationDeniedException;
            }
            $this->incrementMembershipVersion($actor, $targetMembershipId);
            $this->assertEffectiveAdminRemains($actor);
            $this->audit->append($actor, 'tenant_staff.permission_revoked', $this->staffUserFor($actor, $targetMembershipId));
        });
    }

    private function roleForUpdate(TenantStaffContext $actor, string $id): object
    {
        $role = DB::connection(self::CONNECTION)->table('roles')->where('tenant_id', $actor->tenantId)
            ->where('id', $id)->lockForUpdate()->first(['id', 'status', 'version']);
        if (! $role || $role->status !== 'ACTIVE') {
            throw new AuthorizationDeniedException;
        }
        return $role;
    }

    private function denyOwnRoleEdit(TenantStaffContext $actor, string $roleId): void
    {
        // Keep exists() on a granted column; see TenantStaffAccountService::createStaffMember.
        if (DB::connection(self::CONNECTION)->table('tenant_staff_membership_roles')
            ->where('tenant_id', $actor->tenantId)->where('membership_id', $actor->membershipId)
            ->where('role_id', $roleId)->whereNull('revoked_at')->select('role_id')->exists()) {
            throw new AuthorizationDeniedException;
        }
    }

    private function targetMembershipForUpdate(TenantStaffContext $actor, string $id, bool $mustBeActive): object
    {
        if ($id === $actor->membershipId) {
            throw new AuthorizationDeniedException;
        }
        $membership = DB::connection(self::CONNECTION)->table('tenant_staff_memberships')
            ->where('tenant_id', $actor->tenantId)->where('id', $id)->lockForUpdate()->first(['id', 'status']);
        if (! $membership || ($mustBeActive && $membership->status !== 'ACTIVE')) {
            throw new AuthorizationDeniedException;
        }
        return $membership;
    }

    private function staffUserFor(TenantStaffContext $actor, string $membershipId): string
    {
        return (string) DB::connection(self::CONNECTION)->table('tenant_staff_memberships')
            ->where('tenant_id', $actor->tenantId)->where('id', $membershipId)->value('staff_user_id');
    }

    private function incrementMembershipVersion(TenantStaffContext $actor, string $id): void
    {
        DB::connection(self::CONNECTION)->table('tenant_staff_memberships')
            ->where('tenant_id', $actor->tenantId)->where('id', $id)
            ->increment('authorization_version', 1, ['updated_at' => now()]);
    }

    private function assertEffectiveAdminRemains(TenantStaffContext $actor): void
    {
        $this->adminInvariant->assertRemains($actor->tenantId);
    }
}
