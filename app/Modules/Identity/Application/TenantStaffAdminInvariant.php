<?php

namespace App\Modules\Identity\Application;

use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Support\Facades\DB;

/** Tenant-staff analogue of App\Modules\Tenancy\Application\TenantAdminInvariant. */
final class TenantStaffAdminInvariant
{
    public function assertRemains(string $tenantId): void
    {
        $count = DB::connection('pgsql_tenant_runtime')->table('tenant_staff_memberships as m')
            ->join('tenant_staff_users as u', 'u.id', '=', 'm.staff_user_id')
            ->join('tenant_staff_membership_roles as mr', function ($join): void {
                $join->on('mr.tenant_id', '=', 'm.tenant_id')->on('mr.membership_id', '=', 'm.id');
            })
            ->whereNull('mr.revoked_at')
            ->join('roles as r', function ($join): void {
                $join->on('r.tenant_id', '=', 'mr.tenant_id')->on('r.id', '=', 'mr.role_id');
            })
            ->join('role_permissions as rp', function ($join): void {
                $join->on('rp.tenant_id', '=', 'r.tenant_id')->on('rp.role_id', '=', 'r.id');
            })
            ->join('permissions as p', 'p.key', '=', 'rp.permission_key')
            ->where('m.tenant_id', $tenantId)->where('m.status', 'ACTIVE')
            ->where('u.status', 'ACTIVE')->where('r.status', 'ACTIVE')->whereNull('r.archived_at')
            ->where('p.status', 'ACTIVE')->where('p.scopeable', true)
            ->where('p.key', 'company.administer')->where('rp.scope', 'ALL_TENANT')
            ->whereJsonContains('p.allowed_scopes', 'ALL_TENANT')
            ->distinct()->count('m.id');

        if ($count < 1) {
            throw new AuthorizationDeniedException;
        }
    }
}
