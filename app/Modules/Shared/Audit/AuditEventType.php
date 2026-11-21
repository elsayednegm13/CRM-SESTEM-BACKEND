<?php

namespace App\Modules\Shared\Audit;

enum AuditEventType: string
{
    case ROLE_CREATED = 'role.created';
    case ROLE_GRANTS_CHANGED = 'role.grants_changed';
    case ROLE_ARCHIVED = 'role.archived';
    case ROLE_ASSIGNED = 'role.assigned';
    case ROLE_REVOKED = 'role.revoked';
    case MEMBERSHIP_SUSPENDED = 'membership.suspended';
    case MEMBERSHIP_REACTIVATED = 'membership.reactivated';
    case USER_DISABLED = 'user.disabled';
    case COMPANY_ADMIN_BOOTSTRAPPED = 'tenant.company_admin_bootstrapped';
    case PROVIDER_MFA_ENROLLED = 'provider.mfa.enrolled';
    case PROVIDER_RECOVERY_CODE_USED = 'provider.mfa.recovery_code_used';
    case PROVIDER_APPROVAL_REQUESTED = 'provider.approval.requested';
    case PROVIDER_APPROVAL_APPROVED = 'provider.approval.approved';
    case PROVIDER_APPROVAL_REJECTED = 'provider.approval.rejected';
    case PROVIDER_APPROVAL_REVOKED = 'provider.approval.revoked';
    case PROVIDER_CONTROL_OPERATION_CREATED = 'provider.control_operation.created';
    case PROVIDER_CONTROL_OPERATION_EDITED = 'provider.control_operation.edited';
    case PROVIDER_CONTROL_OPERATION_CANCELLED = 'provider.control_operation.cancelled';
    case TENANT_PROVISIONING_EXECUTED = 'tenant.provisioning.executed';
    case TENANT_RECOVERY_EXECUTED = 'tenant.recovery.executed';
    case TENANT_FOUNDER_INVITATION_ACCEPTED = 'tenant.founder_invitation.accepted';
    case TENANT_ACTIVATED = 'tenant.activated';
    case TENANT_LIFECYCLE_CHANGED = 'tenant.lifecycle.changed';
    case PROVIDER_TEAM_MEMBER_CREATED = 'provider.team.member_created';
    case PROVIDER_CAPABILITY_GRANTED = 'provider.capability.granted';
    case PROVIDER_CAPABILITY_REVOKED = 'provider.capability.revoked';
    case PROVIDER_USER_STATUS_CHANGED = 'provider.user.status_changed';
    case PROVIDER_CONTROL_OPERATION_ROOT_BYPASSED = 'provider.control_operation.root_bypassed';
    case PROVIDER_PLAN_CREATED = 'provider.plan.created';
    case PROVIDER_PLAN_UPDATED = 'provider.plan.updated';
    case PROVIDER_PLAN_LIMIT_SET = 'provider.plan.limit_set';
    case TENANT_SUBSCRIPTION_ASSIGNED = 'tenant.subscription.assigned';
    case TENANT_SUBSCRIPTION_CANCELLED = 'tenant.subscription.cancelled';
    case TENANT_LIMIT_OVERRIDE_SET = 'tenant.limit_override.set';
    case TENANT_LIMIT_OVERRIDE_REMOVED = 'tenant.limit_override.removed';

    public function category(): string
    {
        return match ($this) {
            self::ROLE_CREATED, self::ROLE_GRANTS_CHANGED, self::ROLE_ARCHIVED,
            self::ROLE_ASSIGNED, self::ROLE_REVOKED => 'AUTHORIZATION',
            self::MEMBERSHIP_SUSPENDED, self::MEMBERSHIP_REACTIVATED,
            self::COMPANY_ADMIN_BOOTSTRAPPED => 'TENANT_SECURITY',
            self::USER_DISABLED => 'IDENTITY_SECURITY',
            self::PROVIDER_MFA_ENROLLED, self::PROVIDER_RECOVERY_CODE_USED,
            self::PROVIDER_APPROVAL_REQUESTED, self::PROVIDER_APPROVAL_APPROVED,
            self::PROVIDER_APPROVAL_REJECTED, self::PROVIDER_APPROVAL_REVOKED,
            self::PROVIDER_CONTROL_OPERATION_CREATED, self::PROVIDER_CONTROL_OPERATION_EDITED,
            self::PROVIDER_CONTROL_OPERATION_CANCELLED,
            self::PROVIDER_TEAM_MEMBER_CREATED, self::PROVIDER_CAPABILITY_GRANTED,
            self::PROVIDER_CAPABILITY_REVOKED, self::PROVIDER_USER_STATUS_CHANGED,
            self::PROVIDER_CONTROL_OPERATION_ROOT_BYPASSED,
            self::PROVIDER_PLAN_CREATED, self::PROVIDER_PLAN_UPDATED, self::PROVIDER_PLAN_LIMIT_SET,
            self::TENANT_SUBSCRIPTION_ASSIGNED, self::TENANT_SUBSCRIPTION_CANCELLED,
            self::TENANT_LIMIT_OVERRIDE_SET, self::TENANT_LIMIT_OVERRIDE_REMOVED => 'PROVIDER_SECURITY',
            self::TENANT_PROVISIONING_EXECUTED, self::TENANT_RECOVERY_EXECUTED,
            self::TENANT_ACTIVATED, self::TENANT_LIFECYCLE_CHANGED => 'TENANT_SECURITY',
            self::TENANT_FOUNDER_INVITATION_ACCEPTED => 'IDENTITY_SECURITY',
        };
    }

    public function targetType(): string
    {
        return match ($this) {
            self::ROLE_CREATED, self::ROLE_GRANTS_CHANGED, self::ROLE_ARCHIVED => 'role',
            self::ROLE_ASSIGNED, self::ROLE_REVOKED,
            self::MEMBERSHIP_SUSPENDED, self::MEMBERSHIP_REACTIVATED => 'membership',
            self::USER_DISABLED => 'user',
            self::COMPANY_ADMIN_BOOTSTRAPPED => 'tenant',
            self::PROVIDER_MFA_ENROLLED, self::PROVIDER_RECOVERY_CODE_USED,
            self::PROVIDER_TEAM_MEMBER_CREATED, self::PROVIDER_CAPABILITY_GRANTED,
            self::PROVIDER_CAPABILITY_REVOKED, self::PROVIDER_USER_STATUS_CHANGED => 'provider_user',
            self::PROVIDER_APPROVAL_REQUESTED, self::PROVIDER_APPROVAL_APPROVED,
            self::PROVIDER_APPROVAL_REJECTED, self::PROVIDER_APPROVAL_REVOKED,
            self::PROVIDER_CONTROL_OPERATION_ROOT_BYPASSED => 'approval_request',
            self::PROVIDER_CONTROL_OPERATION_CREATED, self::PROVIDER_CONTROL_OPERATION_EDITED,
            self::PROVIDER_CONTROL_OPERATION_CANCELLED => 'provider_control_operation',
            self::TENANT_PROVISIONING_EXECUTED, self::TENANT_RECOVERY_EXECUTED,
            self::TENANT_ACTIVATED, self::TENANT_LIFECYCLE_CHANGED,
            self::TENANT_SUBSCRIPTION_ASSIGNED, self::TENANT_SUBSCRIPTION_CANCELLED,
            self::TENANT_LIMIT_OVERRIDE_SET, self::TENANT_LIMIT_OVERRIDE_REMOVED => 'tenant',
            self::TENANT_FOUNDER_INVITATION_ACCEPTED => 'tenant_founder_invitation',
            self::PROVIDER_PLAN_CREATED, self::PROVIDER_PLAN_UPDATED, self::PROVIDER_PLAN_LIMIT_SET => 'plan',
        };
    }

    public function metadata(array $metadata = []): array
    {
        if ($this === self::PROVIDER_CONTROL_OPERATION_EDITED) {
            $fields = $metadata['changed_fields'] ?? null;
            if (array_keys($metadata) !== ['before_digest', 'after_digest', 'revision', 'changed_fields']
                || ! is_string($metadata['before_digest']) || ! preg_match('/^[a-f0-9]{64}$/D', $metadata['before_digest'])
                || ! is_string($metadata['after_digest']) || ! preg_match('/^[a-f0-9]{64}$/D', $metadata['after_digest'])
                || ! is_int($metadata['revision']) || $metadata['revision'] < 2
                || ! is_array($fields) || count($fields) < 1 || count($fields) > 5
                || array_values(array_unique($fields)) !== array_values($fields)
                || array_diff($fields, ['display_name', 'canonical_slug', 'timezone', 'founder_email', 'first_admin_display_name']) !== []) {
                throw new \LogicException('Invalid Provider edit audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::TENANT_PROVISIONING_EXECUTED && $metadata === []) {
            return [];
        }
        if ($this === self::PROVIDER_CAPABILITY_GRANTED || $this === self::PROVIDER_CAPABILITY_REVOKED) {
            $key = $metadata['capability_key'] ?? null;
            if (array_keys($metadata) !== ['capability_key'] || ! is_string($key)
                || ! preg_match('/^[a-z][a-z0-9_.]{0,62}[a-z0-9]$/D', $key)) {
                throw new \LogicException('Invalid provider capability audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::PROVIDER_USER_STATUS_CHANGED) {
            $before = $metadata['before_status'] ?? null;
            $after = $metadata['after_status'] ?? null;
            if (array_keys($metadata) !== ['before_status', 'after_status']
                || ! in_array($before, ['ACTIVE', 'DISABLED'], true)
                || ! in_array($after, ['ACTIVE', 'DISABLED'], true)
                || $before === $after) {
                throw new \LogicException('Invalid provider user status audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::PROVIDER_TEAM_MEMBER_CREATED && $metadata === []) {
            return [];
        }
        if ($this === self::PROVIDER_CONTROL_OPERATION_ROOT_BYPASSED) {
            $action = $metadata['action_key'] ?? null;
            if (array_keys($metadata) !== ['action_key']
                || ! in_array($action, ['company.provision', 'company.recover', 'company.lifecycle.manage'], true)) {
                throw new \LogicException('Invalid root-bypass audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::PROVIDER_PLAN_CREATED && $metadata === []) {
            return [];
        }
        if ($this === self::PROVIDER_PLAN_UPDATED) {
            $fields = $metadata['changed_fields'] ?? null;
            if (array_keys($metadata) !== ['changed_fields'] || ! is_array($fields) || count($fields) < 1 || count($fields) > 4
                || array_values(array_unique($fields)) !== array_values($fields)
                || array_diff($fields, ['display_name', 'price_monthly_minor', 'price_annual_minor', 'status']) !== []) {
                throw new \LogicException('Invalid plan-update audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::PROVIDER_PLAN_LIMIT_SET || $this === self::TENANT_LIMIT_OVERRIDE_SET
            || $this === self::TENANT_LIMIT_OVERRIDE_REMOVED) {
            $key = $metadata['limit_key'] ?? null;
            if (array_keys($metadata) !== ['limit_key'] || ! is_string($key)
                || ! preg_match('/^[a-z][a-z0-9_]{0,62}[a-z0-9]$/D', $key)) {
                throw new \LogicException('Invalid limit audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::TENANT_SUBSCRIPTION_ASSIGNED) {
            $planId = $metadata['plan_id'] ?? null;
            if (array_keys($metadata) !== ['plan_id'] || ! is_string($planId) || ! \Illuminate\Support\Str::isUuid($planId)) {
                throw new \LogicException('Invalid subscription audit metadata.');
            }
            return $metadata;
        }
        if ($this === self::TENANT_SUBSCRIPTION_CANCELLED && $metadata === []) {
            return [];
        }
        if ($this === self::TENANT_LIFECYCLE_CHANGED) {
            $before = $metadata['before_status'] ?? null;
            $after = $metadata['after_status'] ?? null;
            if (array_keys($metadata) !== ['before_status', 'after_status']
                || ! in_array($before, ['ACTIVE', 'SUSPENDED'], true)
                || ! in_array($after, ['ACTIVE', 'SUSPENDED', 'ARCHIVED'], true)
                || $before === $after) {
                throw new \LogicException('Invalid tenant lifecycle audit metadata.');
            }
            return $metadata;
        }

        $expected = match ($this) {
            self::ROLE_GRANTS_CHANGED => ['changed_fields' => ['grants']],
            self::MEMBERSHIP_SUSPENDED => ['before_status' => 'ACTIVE', 'after_status' => 'SUSPENDED'],
            self::MEMBERSHIP_REACTIVATED => ['before_status' => 'SUSPENDED', 'after_status' => 'ACTIVE'],
            self::TENANT_PROVISIONING_EXECUTED => ['founder_invitation_id' => $metadata['founder_invitation_id'] ?? null],
            self::TENANT_FOUNDER_INVITATION_ACCEPTED, self::TENANT_ACTIVATED => ['membership_id' => $metadata['membership_id'] ?? null],
            self::TENANT_RECOVERY_EXECUTED => [
                'successor_user_id' => $metadata['successor_user_id'] ?? null,
                'successor_membership_id' => $metadata['successor_membership_id'] ?? null,
                'compromised_membership_id' => $metadata['compromised_membership_id'] ?? null,
            ],
            default => [],
        };
        $dynamic = in_array($this, [self::TENANT_PROVISIONING_EXECUTED, self::TENANT_RECOVERY_EXECUTED,
            self::TENANT_FOUNDER_INVITATION_ACCEPTED, self::TENANT_ACTIVATED], true);
        if ($metadata === [] && ! $dynamic) {
            return $expected;
        }
        if (array_keys($metadata) !== array_keys($expected)) {
            throw new \LogicException('Invalid security audit metadata.');
        }
        if (! $dynamic) {
            return $expected;
        }
        foreach ($metadata as $key => $value) {
            if ($key !== 'compromised_membership_id' && (! is_string($value) || ! \Illuminate\Support\Str::isUuid($value))) {
                throw new \LogicException('Invalid security audit metadata.');
            }
            if ($key === 'compromised_membership_id' && $value !== null && (! is_string($value) || ! \Illuminate\Support\Str::isUuid($value))) {
                throw new \LogicException('Invalid security audit metadata.');
            }
        }

        return $expected;
    }

    public function isTenantMutation(): bool
    {
        return in_array($this, [self::ROLE_CREATED, self::ROLE_GRANTS_CHANGED, self::ROLE_ARCHIVED,
            self::ROLE_ASSIGNED, self::ROLE_REVOKED, self::MEMBERSHIP_SUSPENDED,
            self::MEMBERSHIP_REACTIVATED], true);
    }

    public function isProviderMutation(): bool
    {
        return in_array($this, [self::PROVIDER_MFA_ENROLLED, self::PROVIDER_RECOVERY_CODE_USED,
            self::PROVIDER_APPROVAL_REQUESTED, self::PROVIDER_APPROVAL_APPROVED,
            self::PROVIDER_APPROVAL_REJECTED, self::PROVIDER_APPROVAL_REVOKED,
            self::PROVIDER_TEAM_MEMBER_CREATED, self::PROVIDER_CAPABILITY_GRANTED,
            self::PROVIDER_CAPABILITY_REVOKED, self::PROVIDER_USER_STATUS_CHANGED,
            self::PROVIDER_PLAN_CREATED, self::PROVIDER_PLAN_UPDATED, self::PROVIDER_PLAN_LIMIT_SET,
            self::TENANT_SUBSCRIPTION_ASSIGNED, self::TENANT_SUBSCRIPTION_CANCELLED,
            self::TENANT_LIMIT_OVERRIDE_SET, self::TENANT_LIMIT_OVERRIDE_REMOVED], true);
    }

    /** True for provider-mode events that are scoped to a target tenant (not global). */
    public function isProviderTenantScopedMutation(): bool
    {
        return in_array($this, [self::TENANT_SUBSCRIPTION_ASSIGNED, self::TENANT_SUBSCRIPTION_CANCELLED,
            self::TENANT_LIMIT_OVERRIDE_SET, self::TENANT_LIMIT_OVERRIDE_REMOVED], true);
    }

    public function isProviderControlMutation(): bool
    {
        return in_array($this, [self::PROVIDER_CONTROL_OPERATION_CREATED, self::PROVIDER_CONTROL_OPERATION_EDITED,
            self::PROVIDER_CONTROL_OPERATION_CANCELLED,
            self::PROVIDER_APPROVAL_REQUESTED, self::PROVIDER_APPROVAL_APPROVED,
            self::PROVIDER_APPROVAL_REJECTED, self::PROVIDER_APPROVAL_REVOKED,
            self::TENANT_PROVISIONING_EXECUTED, self::TENANT_RECOVERY_EXECUTED,
            self::TENANT_LIFECYCLE_CHANGED, self::PROVIDER_CONTROL_OPERATION_ROOT_BYPASSED], true);
    }

    public function isFounderActivation(): bool
    {
        return in_array($this, [self::TENANT_FOUNDER_INVITATION_ACCEPTED, self::TENANT_ACTIVATED], true);
    }
}
