<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\EffectivePermissions;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Support\Facades\DB;

final class TenantStaffEffectiveAuthorizationService
{
    public function __construct(private readonly EffectivePermissions $permissions)
    {
    }

    /**
     * Return the authenticated membership's current effective catalog permissions.
     *
     * @return array<int, array{key:string,scopes:?array<int,string>,scopeable:bool,delegable:bool}>
     */
    public function snapshot(TenantStaffContext $context): array
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
            ->get(['role.id as role_id']);

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

        $keys = $roleGrants->pluck('permission_key')
            ->merge($directGrants->pluck('permission_key'))
            ->unique()
            ->values();
        $catalog = $keys->isEmpty() ? collect() : $connection->table('permissions')
            ->whereIn('key', $keys->all())
            ->get(['key', 'status', 'scopeable', 'allowed_scopes', 'delegable'])
            ->keyBy('key');

        $resolved = $this->permissions->resolve(
            $roleGrants->map(fn ($grant): array => [
                'permission_key' => $grant->permission_key,
                'scope' => $grant->scope,
            ])->all(),
            $directGrants->map(fn ($grant): array => [
                'permission_key' => $grant->permission_key,
                'scope' => $grant->scope,
            ])->all(),
            $catalog->map(fn ($permission): array => [
                'status' => $permission->status,
                'scopeable' => $this->databaseBoolean($permission->scopeable),
                'allowed_scopes' => $this->allowedScopes($permission->allowed_scopes),
                'delegable' => $this->databaseBoolean($permission->delegable),
            ])->all(),
        );

        if ($resolved === null) {
            throw new AuthorizationDeniedException;
        }

        $snapshot = [];
        foreach ($resolved as $key => $scopes) {
            $metadata = $catalog->get($key);
            if ($metadata === null) {
                throw new AuthorizationDeniedException;
            }

            $scopeable = $this->databaseBoolean($metadata->scopeable);
            $delegable = $this->databaseBoolean($metadata->delegable);
            if (! is_bool($scopeable) || ! is_bool($delegable)) {
                throw new AuthorizationDeniedException;
            }

            $snapshot[] = [
                'key' => $key,
                'scopes' => $scopes === [null] ? null : $scopes,
                'scopeable' => $scopeable,
                'delegable' => $delegable,
            ];
        }

        return $snapshot;
    }

    private function allowedScopes(mixed $value): ?array
    {
        if (is_array($value)) {
            return $value;
        }

        if (! is_string($value)) {
            return null;
        }

        $decoded = json_decode($value, true);

        return is_array($decoded) ? $decoded : null;
    }

    private function databaseBoolean(mixed $value): ?bool
    {
        if (is_bool($value)) {
            return $value;
        }

        if ($value === 1 || $value === '1' || $value === 't' || $value === 'true') {
            return true;
        }

        if ($value === 0 || $value === '0' || $value === 'f' || $value === 'false') {
            return false;
        }

        return null;
    }
}
