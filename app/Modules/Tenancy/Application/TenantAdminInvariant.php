<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Support\Facades\DB;

/** Call under the tenant row write lock after any change that can remove an admin. */
final class TenantAdminInvariant
{
    public function assertRemains(string $tenantId): void
    {
        $count = DB::table('tenant_memberships as m')
            ->join('users as u', 'u.id', '=', 'm.user_id')
            ->join('membership_roles as mr', function ($join): void {
                $join->on('mr.tenant_id', '=', 'm.tenant_id')->on('mr.membership_id', '=', 'm.id');
            })
            ->join('roles as r', function ($join): void {
                $join->on('r.tenant_id', '=', 'mr.tenant_id')->on('r.id', '=', 'mr.role_id');
            })
            ->join('role_permissions as rp', function ($join): void {
                $join->on('rp.tenant_id', '=', 'r.tenant_id')->on('rp.role_id', '=', 'r.id');
            })
            ->join('permissions as p', 'p.key', '=', 'rp.permission_key')
            ->where('m.tenant_id', $tenantId)->where('m.status', 'ACTIVE')
            ->where('u.status', 'ACTIVE')->where('r.status', 'ACTIVE')
            ->where('p.status', 'ACTIVE')->where('p.scopeable', true)
            ->where('p.key', 'company.administer')->where('rp.scope', 'ALL_TENANT')
            ->whereJsonContains('p.allowed_scopes', 'ALL_TENANT')
            ->distinct()->count('m.id');

        if ($count < 1) {
            throw new AuthorizationDeniedException;
        }
    }
}
