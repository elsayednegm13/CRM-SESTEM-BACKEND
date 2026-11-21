<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Shared\Audit\TenantStaffAuditWriter;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Company-admin-driven staff account management. Provider creates the first Company Admin
 * (ProviderControlOperationService::executeProvision()); a Company Admin directly creates
 * employees within the same tenant from here on -- no invitation entity, per
 * docs/TENANT_STAFF_IDENTITY_AND_RBAC_FOUNDATION.md. Every write uses pgsql_tenant_runtime
 * explicitly, same reasoning as TenantStaffRoleMutationService.
 */
final class TenantStaffAccountService
{
    private const CONNECTION = 'pgsql_tenant_runtime';

    public function __construct(
        private readonly TenantStaffAuthorizationService $authorization,
        private readonly TenantStaffAccountFactory $factory,
        private readonly TenantStaffAdminInvariant $adminInvariant,
        private readonly TenantStaffAuditWriter $audit,
        private readonly TenantStaffRoleMutationService $roles,
    ) {}

    /** @return array<int,array{membership_id:string,staff_user_id:string,email:string,name:string,status:string}> */
    public function listStaff(TenantStaffContext $actor): array
    {
        return $this->authorization->runWithCapability($actor, 'member.view', function () use ($actor): array {
            return DB::connection(self::CONNECTION)->table('tenant_staff_memberships as m')
                ->join('tenant_staff_users as u', 'u.id', '=', 'm.staff_user_id')
                ->where('m.tenant_id', $actor->tenantId)
                ->orderBy('u.display_name')
                ->get(['m.id as membership_id', 'u.id as staff_user_id', 'u.display_email', 'u.display_name', 'm.status'])
                ->map(fn ($row): array => ['membership_id' => $row->membership_id, 'staff_user_id' => $row->staff_user_id,
                    'email' => $row->display_email, 'name' => $row->display_name, 'status' => $row->status])
                ->all();
        });
    }

    /** @return array{membership_id:string,staff_user_id:string} */
    public function createStaffMember(TenantStaffContext $actor, string $email, string $displayName,
        string $initialPassword, ?string $roleId = null): array
    {
        return $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $email, $displayName, $initialPassword, $roleId): array {
            $connection = DB::connection(self::CONNECTION);
            $payload = $this->factory->build($actor->tenantId, $email, $displayName, $initialPassword);
            // select('id') keeps exists() off `SELECT *`: the runtime role has no SELECT on
            // password_hash, so the implicit star query is denied (42501).
            if ($connection->table('tenant_staff_users')->where('tenant_id', $actor->tenantId)
                ->where('canonical_email', $payload['canonical_email'])->select('id')->exists()) {
                throw ValidationException::withMessages(['email' => ['A staff account with this email already exists.']]);
            }
            $connection->table('tenant_staff_users')->insert($payload);
            $membershipId = (string) \Illuminate\Support\Str::uuid7();
            $now = now('UTC');
            $connection->table('tenant_staff_memberships')->insert([
                'id' => $membershipId, 'tenant_id' => $actor->tenantId, 'staff_user_id' => $payload['id'],
                'status' => 'ACTIVE', 'authorization_version' => 1, 'joined_at' => $now,
                'created_by_membership_id' => $actor->membershipId,
                'created_at' => $now, 'updated_at' => $now,
            ]);
            $this->audit->append($actor, 'tenant_staff.created', $payload['id']);
            if ($roleId !== null) {
                $this->roles->assignRole($actor, $membershipId, $roleId);
            }
            return ['membership_id' => $membershipId, 'staff_user_id' => $payload['id']];
        });
    }

    public function disableStaffMember(TenantStaffContext $actor, string $targetMembershipId): void
    {
        $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId): void {
            if ($targetMembershipId === $actor->membershipId) {
                throw new AuthorizationDeniedException;
            }
            $connection = DB::connection(self::CONNECTION);
            $membership = $connection->table('tenant_staff_memberships')->where('tenant_id', $actor->tenantId)
                ->where('id', $targetMembershipId)->lockForUpdate()->first(['id', 'status', 'staff_user_id']);
            if (! $membership || $membership->status !== 'ACTIVE') {
                throw new AuthorizationDeniedException;
            }
            $connection->table('tenant_staff_memberships')->where('tenant_id', $actor->tenantId)->where('id', $targetMembershipId)
                ->update(['status' => 'SUSPENDED', 'authorization_version' => DB::raw('authorization_version + 1'), 'updated_at' => now('UTC')]);
            $this->adminInvariant->assertRemains($actor->tenantId);
            $this->audit->append($actor, 'tenant_staff.disabled', $membership->staff_user_id);
        });
    }

    public function reactivateStaffMember(TenantStaffContext $actor, string $targetMembershipId): void
    {
        $this->authorization->runWithCapability($actor, 'member.manage', function () use ($actor, $targetMembershipId): void {
            if ($targetMembershipId === $actor->membershipId) {
                throw new AuthorizationDeniedException;
            }
            $connection = DB::connection(self::CONNECTION);
            $membership = $connection->table('tenant_staff_memberships')->where('tenant_id', $actor->tenantId)
                ->where('id', $targetMembershipId)->lockForUpdate()->first(['id', 'status', 'staff_user_id']);
            if (! $membership || $membership->status !== 'SUSPENDED') {
                throw new AuthorizationDeniedException;
            }
            $staff = $connection->table('tenant_staff_users')->where('tenant_id', $actor->tenantId)
                ->where('id', $membership->staff_user_id)->first(['status']);
            if (! $staff || $staff->status !== 'ACTIVE') {
                throw new AuthorizationDeniedException;
            }
            $connection->table('tenant_staff_memberships')->where('tenant_id', $actor->tenantId)->where('id', $targetMembershipId)
                ->update(['status' => 'ACTIVE', 'authorization_version' => DB::raw('authorization_version + 1'), 'updated_at' => now('UTC')]);
            $this->audit->append($actor, 'tenant_staff.reactivated', $membership->staff_user_id);
        });
    }
}
