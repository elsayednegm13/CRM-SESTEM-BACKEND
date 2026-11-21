<?php

namespace App\Modules\Shared\Audit;

use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

/**
 * Writer for tenant_staff_security_events (migrations 2026_10_11_000025,
 * 2026_10_23_000035) -- a dedicated audit table distinct from the shared security_audit_events
 * table that SecurityAuditWriter writes. Fixed event vocabulary, always-empty metadata,
 * append-only by DB trigger. Events target either a staff member or a role, never both -- the
 * DB CHECK (tsse_target_check) enforces this independently of the two append methods below.
 */
final class TenantStaffAuditWriter
{
    private const STAFF_TARGETED_EVENT_TYPES = [
        'tenant_staff.created', 'tenant_staff.email_changed', 'tenant_staff.disabled',
        'tenant_staff.reactivated', 'tenant_staff.password_set', 'tenant_staff.password_reset_completed',
        'tenant_staff.role_assigned', 'tenant_staff.role_revoked',
        'tenant_staff.permission_granted', 'tenant_staff.permission_revoked', 'tenant_staff.auth_denied',
    ];

    private const ROLE_TARGETED_EVENT_TYPES = [
        'tenant_staff.role_created', 'tenant_staff.role_grants_changed', 'tenant_staff.role_archived',
    ];

    public function append(TenantStaffContext $actor, string $eventType, string $targetStaffUserId): string
    {
        if (! in_array($eventType, self::STAFF_TARGETED_EVENT_TYPES, true) || ! Str::isUuid($targetStaffUserId)) {
            throw new LogicException('Invalid staff-targeted tenant-staff audit event.');
        }

        return $this->insert($actor, $eventType, $targetStaffUserId, null);
    }

    public function appendForRole(TenantStaffContext $actor, string $eventType, string $targetRoleId): string
    {
        if (! in_array($eventType, self::ROLE_TARGETED_EVENT_TYPES, true) || ! Str::isUuid($targetRoleId)) {
            throw new LogicException('Invalid role-targeted tenant-staff audit event.');
        }

        return $this->insert($actor, $eventType, null, $targetRoleId);
    }

    private function insert(TenantStaffContext $actor, string $eventType, ?string $targetStaffUserId, ?string $targetRoleId): string
    {
        $id = (string) Str::uuid7();
        DB::connection('pgsql_tenant_runtime')->table('tenant_staff_security_events')->insert([
            'id' => $id, 'occurred_at' => now('UTC'), 'tenant_id' => $actor->tenantId,
            'event_type' => $eventType, 'outcome' => 'SUCCESS', 'request_id' => null,
            'actor_membership_id' => $actor->membershipId,
            'target_staff_user_id' => $targetStaffUserId, 'target_role_id' => $targetRoleId, 'metadata' => '{}',
        ]);

        return $id;
    }
}
