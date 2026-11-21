<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\EffectivePermissions;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\ResourceScope;
use Illuminate\Support\Facades\DB;

final class TenantStaffAuthorizationService
{
    public function __construct(private readonly EffectivePermissions $permissions)
    {
    }

    /** @return array<int,array{id:string,name:string}> */
    public function listRoles(TenantStaffContext $context): array
    {
        $grants = $this->effectiveGrants($context);
        if (! array_key_exists('role.view', $grants)) {
            throw new AuthorizationDeniedException;
        }
        $connection = DB::connection('pgsql_tenant_runtime');

        return $connection->table('roles')
            ->where('tenant_id', $context->tenantId)
            ->where('status', 'ACTIVE')
            ->whereNull('archived_at')
            ->orderBy('normalized_name')
            ->get(['id', 'display_name'])
            ->map(fn ($role): array => ['id' => $role->id, 'name' => $role->display_name])
            ->all();
    }

    /**
     * Runs $operation only if $permission is held (non-scopeable presence check); returns the
     * effective-grants map to $operation so it can run further canDelegate() checks itself.
     */
    public function runWithCapability(TenantStaffContext $context, string $permission, \Closure $operation): mixed
    {
        $grants = $this->effectiveGrants($context);
        if (! in_array(null, $grants[$permission] ?? [], true)) {
            throw new AuthorizationDeniedException;
        }

        return $operation($grants);
    }

    /** @param array<string, array<int,?string>> $actorGrants */
    public function canDelegate(array $actorGrants, string $permission, ?string $proposedScope): bool
    {
        if ($permission === 'company.administer') {
            return false;
        }
        $metadata = $this->catalog($permission);
        if (! $metadata || ! $metadata->delegable) {
            return false;
        }
        $owned = $actorGrants[$permission] ?? [];
        if (! $metadata->scopeable) {
            return $proposedScope === null && in_array(null, $owned, true);
        }
        $allowed = json_decode($metadata->allowed_scopes, true, 512, JSON_THROW_ON_ERROR);
        if ($proposedScope === null || $proposedScope === ResourceScope::NONE->value
            || $proposedScope === ResourceScope::TEAM->value
            || ! in_array($proposedScope, $allowed, true)) {
            return false;
        }

        return in_array(ResourceScope::ALL_TENANT->value, $owned, true) || in_array($proposedScope, $owned, true);
    }

    /** @return array<string, array<int,?string>> permission key => list of scopes (null = non-scopeable presence) */
    public function effectiveGrants(TenantStaffContext $context): array
    {
        $connection = DB::connection('pgsql_tenant_runtime');
        $assignedRoles = $connection->table('tenant_staff_membership_roles as assignment')
            ->join('roles as role', function ($join): void {
                $join->on('role.tenant_id', '=', 'assignment.tenant_id')
                    ->on('role.id', '=', 'assignment.role_id');
            })
            ->where('assignment.tenant_id', $context->tenantId)
            ->where('assignment.membership_id', $context->membershipId)
            ->whereNull('assignment.revoked_at')
            ->where('role.status', 'ACTIVE')
            ->whereNull('role.archived_at')
            ->get(['assignment.role_id']);

        $roleIds = $assignedRoles->pluck('role_id')->unique()->values()->all();
        $roleGrants = $roleIds === [] ? collect() : $connection->table('role_permissions')
            ->where('tenant_id', $context->tenantId)
            ->whereIn('role_id', $roleIds)
            ->get(['permission_key', 'scope']);
        $directGrants = $connection->table('tenant_staff_permission_grants')
            ->where('tenant_id', $context->tenantId)
            ->where('membership_id', $context->membershipId)
            ->whereNull('revoked_at')
            ->get(['permission_key', 'scope']);

        $keys = $roleGrants->pluck('permission_key')->merge($directGrants->pluck('permission_key'))->unique()->values();
        $catalog = $keys->isEmpty() ? collect() : $connection->table('permissions')
            ->whereIn('key', $keys->all())
            ->get(['key', 'status', 'scopeable', 'allowed_scopes', 'delegable'])
            ->keyBy('key');

        $effective = $this->permissions->resolve(
            $roleGrants->map(fn ($grant): array => ['permission_key' => $grant->permission_key, 'scope' => $grant->scope])->all(),
            $directGrants->map(fn ($grant): array => ['permission_key' => $grant->permission_key, 'scope' => $grant->scope])->all(),
            $catalog->map(fn ($permission): array => [
                'status' => $permission->status,
                'scopeable' => (bool) $permission->scopeable,
                'allowed_scopes' => is_array($permission->allowed_scopes)
                    ? $permission->allowed_scopes
                    : json_decode((string) $permission->allowed_scopes, true, flags: JSON_THROW_ON_ERROR),
                'delegable' => (bool) $permission->delegable,
            ])->all(),
        );

        if ($effective === null) {
            throw new AuthorizationDeniedException;
        }

        return $effective;
    }

    private function catalog(string $permission): ?object
    {
        return DB::connection('pgsql_tenant_runtime')->table('permissions')
            ->where('key', $permission)->where('status', 'ACTIVE')
            ->first(['scopeable', 'allowed_scopes', 'delegable']);
    }
}
