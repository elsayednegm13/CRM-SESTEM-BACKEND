<?php

namespace App\Modules\Provider\Application;

use App\Modules\Identity\Application\TenantStaffAccountFactory;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\EffectivePermissions;
use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\CanonicalTenantHost;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderControlDatabaseContext;
use App\Modules\Provider\Infrastructure\Persistence\TenantHostnameRegistry;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use DomainException;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

/** Provider control-plane operations. Every write and audit row share one PG transaction. */
final class ProviderControlOperationService
{
    public function __construct(
        private readonly ProviderAuthorizationService $authorization,
        private readonly ProviderControlDatabaseContext $context,
        private readonly SecurityAuditWriter $audit,
        private readonly EmailAddressNormalizer $emails,
        private readonly TenantStaffAccountFactory $staffAccounts,
        private readonly TenantHostnameRegistry $hostnames,
        private readonly TenantHostResolver $hostResolver,
        private readonly EffectivePermissions $effectivePermissions,
    ) {}

    public function createProvision(ProviderContext $actor, array $input, string $idempotencyKey): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.provision');
        $display = trim((string) $input['display_name']);
        $slug = strtolower(trim((string) $input['slug']));
        try {
            $email = $this->emails->normalize((string) $input['first_admin_email']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['first_admin_email' => ['The first administrator email is invalid.']]);
        }
        $adminName = trim((string) $input['first_admin_display_name']);
        $timezone = (string) $input['timezone'];
        $reason = trim((string) $input['reason']);
        $ticket = trim((string) $input['ticket_reference']);
        if ($display === '' || mb_strlen($display) > 160 || $adminName === '' || mb_strlen($adminName) > 160
            || preg_match('/[\x00-\x1F\x7F]/u', $adminName) === 1
            || ! preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug)
            || mb_strlen($slug) > 100 || ! filter_var($email, FILTER_VALIDATE_EMAIL)
            || mb_strlen($email) > 254 || ! in_array($timezone, timezone_identifiers_list(), true)
            || $reason === '' || mb_strlen($reason) > 500 || ! preg_match('/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,99}$/D', $ticket)
            || ! preg_match('/^[A-Za-z0-9._:-]{16,128}$/D', $idempotencyKey)) {
            throw ValidationException::withMessages(['operation' => ['The provisioning request is invalid.']]);
        }
        $intent = ['action' => 'company.provision',
            'display_name' => $display, 'slug' => $slug, 'timezone' => $timezone,
            'founder_email' => $email, 'first_admin_display_name' => $adminName,
            'reason' => $reason, 'ticket_reference' => $ticket];
        $keyHash = hash_hmac('sha256', $idempotencyKey, (string) config('app.key'));

        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, 'company.provision', 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $intent, $keyHash): array {
                $this->assertProvider($db, $actor, 'company.provision');
                $db->selectOne('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))', [$keyHash]);
                $existing = $db->table('provider_control_operations')->where('requester_provider_user_id', $actor->providerUserId)
                    ->where('action_key', 'company.provision')->where('idempotency_key_hash', $keyHash)
                    ->first(['id', 'target_tenant_id', 'intent_digest', 'status', 'approval_request_id', 'current_revision']);
                if ($existing) {
                    $digest = hash('sha256', json_encode($intent + ['tenant_id' => $existing->target_tenant_id], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
                    if (! hash_equals($existing->intent_digest, $digest)) {
                        throw ProviderAccessException::approvalUnusable();
                    }
                    return ['id' => $existing->id, 'status' => $existing->status,
                        'approval_request_id' => $existing->approval_request_id,
                        'revision' => (int) $existing->current_revision];
                }
                $tenantId = (string) Str::uuid7();
                $digest = hash('sha256', json_encode($intent + ['tenant_id' => $tenantId], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
                $id = (string) Str::uuid7();
                $approvalId = (string) Str::uuid7();
                $now = now('UTC');
                $expires = $now->copy()->addHours(4);
                $db->table('provider_control_operations')->insert([
                    'id' => $id, 'action_key' => 'company.provision',
                    'requester_provider_user_id' => $actor->providerUserId,
                    'approval_request_id' => null, 'idempotency_key_hash' => $keyHash,
                    'intent_digest' => $digest, 'target_tenant_id' => $tenantId,
                    'status' => 'PENDING_APPROVAL', 'display_name' => $intent['display_name'],
                    'canonical_slug' => $intent['slug'], 'timezone' => $intent['timezone'],
                    'founder_email' => $intent['founder_email'],
                    'first_admin_display_name' => $intent['first_admin_display_name'], 'reason' => $intent['reason'],
                    'ticket_reference' => $intent['ticket_reference'], 'expires_at' => $expires,
                    'created_at' => $now, 'updated_at' => $now,
                ]);
                $db->table('provider_approval_requests')->insert([
                    'id' => $approvalId, 'operation_id' => $id, 'intent_digest' => $digest,
                    'review_revision' => 1,
                    'requester_provider_user_id' => $actor->providerUserId,
                    'action_key' => 'company.provision', 'target_kind' => 'PROVISIONING_INTENT',
                    'target_id' => $tenantId, 'reason' => $intent['reason'],
                    'ticket_reference' => $intent['ticket_reference'], 'required_approvals' => 1,
                    'expires_at' => $expires, 'status' => 'PENDING', 'created_at' => $now, 'updated_at' => $now,
                ]);
                $db->table('provider_control_operations')->where('id', $id)->update(['approval_request_id' => $approvalId]);
                $db->table('provider_provision_revisions')->insert([
                    'operation_id' => $id, 'revision' => 1, 'intent_digest' => $digest,
                    'requester_provider_user_id' => $actor->providerUserId,
                    'changed_fields' => '[]', 'created_at' => $now,
                ]);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::PROVIDER_CONTROL_OPERATION_CREATED, $id);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::PROVIDER_APPROVAL_REQUESTED, $approvalId);
                $status = $this->applyRootBypassIfHeld($db, $actor, $id, $approvalId, 'company.provision');
                return ['id' => $id, 'status' => $status, 'approval_request_id' => $approvalId,
                    'revision' => 1];
            });
    }

    public function createRecovery(ProviderContext $actor, array $input, string $idempotencyKey): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.recover');
        $tenantId = (string) $input['tenant_id'];
        $successorId = (string) $input['successor_user_id'];
        $mode = (string) $input['mode'];
        $compromisedId = $input['compromised_membership_id'] ?? null;
        $reason = trim((string) $input['reason']);
        $ticket = trim((string) $input['ticket_reference']);
        if (! Str::isUuid($tenantId) || ! Str::isUuid($successorId)
            || ($compromisedId !== null && ! Str::isUuid((string) $compromisedId))
            || ! in_array($mode, ['RESTORE_ADMIN', 'REPLACE_ADMIN'], true)
            || ($mode === 'RESTORE_ADMIN' && $compromisedId !== null)
            || ($mode === 'REPLACE_ADMIN' && $compromisedId === null)
            || $reason === '' || mb_strlen($reason) > 500
            || ! preg_match('/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,99}$/D', $ticket)
            || ! preg_match('/^[A-Za-z0-9._:-]{16,128}$/D', $idempotencyKey)) {
            throw ValidationException::withMessages(['operation' => ['The recovery request is invalid.']]);
        }
        $intent = ['action' => 'company.recover', 'tenant_id' => $tenantId,
            'successor_user_id' => $successorId, 'compromised_membership_id' => $compromisedId,
            'mode' => $mode, 'reason' => $reason, 'ticket_reference' => $ticket];
        $digest = hash('sha256', json_encode($intent, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $keyHash = hash_hmac('sha256', $idempotencyKey, (string) config('app.key'));
        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, 'company.recover', 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $intent, $digest, $keyHash): array {
                $this->assertProvider($db, $actor, 'company.recover');
                $db->selectOne('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))', [$keyHash]);
                $old = $db->table('provider_control_operations')->where('requester_provider_user_id', $actor->providerUserId)
                    ->where('action_key', 'company.recover')->where('idempotency_key_hash', $keyHash)->first();
                if ($old) {
                    if (! hash_equals($old->intent_digest, $digest)) { throw ProviderAccessException::approvalUnusable(); }
                    return ['id' => $old->id, 'status' => $old->status, 'approval_request_id' => $old->approval_request_id];
                }
                $id = (string) Str::uuid7(); $approvalId = (string) Str::uuid7(); $now = now('UTC'); $expires = $now->copy()->addHours(4);
                $db->table('provider_control_operations')->insert([
                    'id' => $id, 'action_key' => 'company.recover', 'requester_provider_user_id' => $actor->providerUserId,
                    'approval_request_id' => null, 'idempotency_key_hash' => $keyHash, 'intent_digest' => $digest,
                    'target_tenant_id' => $intent['tenant_id'], 'status' => 'PENDING_APPROVAL',
                    'successor_user_id' => $intent['successor_user_id'], 'compromised_membership_id' => $intent['compromised_membership_id'],
                    'recovery_mode' => $intent['mode'], 'reason' => $intent['reason'], 'ticket_reference' => $intent['ticket_reference'],
                    'expires_at' => $expires, 'created_at' => $now, 'updated_at' => $now,
                ]);
                $db->table('provider_approval_requests')->insert([
                    'id' => $approvalId, 'operation_id' => $id, 'intent_digest' => $digest,
                    'requester_provider_user_id' => $actor->providerUserId, 'action_key' => 'company.recover',
                    'target_kind' => 'TENANT', 'target_id' => $intent['tenant_id'], 'reason' => $intent['reason'],
                    'ticket_reference' => $intent['ticket_reference'], 'required_approvals' => 1,
                    'expires_at' => $expires, 'status' => 'PENDING', 'created_at' => $now, 'updated_at' => $now,
                ]);
                $db->table('provider_control_operations')->where('id', $id)->update(['approval_request_id' => $approvalId]);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::PROVIDER_CONTROL_OPERATION_CREATED, $id);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::PROVIDER_APPROVAL_REQUESTED, $approvalId);
                $status = $this->applyRootBypassIfHeld($db, $actor, $id, $approvalId, 'company.recover');
                return ['id' => $id, 'status' => $status, 'approval_request_id' => $approvalId];
            });
    }

    /** Create a suspend/resume/archive request. Reviewed and executed exactly like company.provision. */
    public function createLifecycleChange(ProviderContext $actor, array $input, string $idempotencyKey): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.lifecycle.manage');
        $tenantId = (string) ($input['tenant_id'] ?? '');
        $action = (string) ($input['action'] ?? '');
        $reason = trim((string) ($input['reason'] ?? ''));
        $ticket = trim((string) ($input['ticket_reference'] ?? ''));
        if (! Str::isUuid($tenantId) || ! in_array($action, ['SUSPEND', 'RESUME', 'ARCHIVE'], true)
            || $reason === '' || mb_strlen($reason) > 500
            || ! preg_match('/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,99}$/D', $ticket)
            || ! preg_match('/^[A-Za-z0-9._:-]{16,128}$/D', $idempotencyKey)) {
            throw ValidationException::withMessages(['operation' => ['The lifecycle request is invalid.']]);
        }
        $intent = ['action' => 'company.lifecycle.manage', 'tenant_id' => $tenantId,
            'lifecycle_action' => $action, 'reason' => $reason, 'ticket_reference' => $ticket];
        $digest = hash('sha256', json_encode($intent, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        $keyHash = hash_hmac('sha256', $idempotencyKey, (string) config('app.key'));
        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, 'company.lifecycle.manage', 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $intent, $digest, $keyHash): array {
                $this->assertProvider($db, $actor, 'company.lifecycle.manage');
                $db->selectOne('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))', [$keyHash]);
                $old = $db->table('provider_control_operations')->where('requester_provider_user_id', $actor->providerUserId)
                    ->where('action_key', 'company.lifecycle.manage')->where('idempotency_key_hash', $keyHash)
                    ->first(['id', 'intent_digest', 'status', 'approval_request_id']);
                if ($old) {
                    if (! hash_equals($old->intent_digest, $digest)) { throw ProviderAccessException::approvalUnusable(); }
                    return ['id' => $old->id, 'status' => $old->status, 'approval_request_id' => $old->approval_request_id];
                }
                // The target tenant's current status is not RLS-visible yet (no provider_control_operations
                // row exists for it until the insert below), exactly like createRecovery(); the real,
                // RLS-enforced status/transition check happens under lock in executeLifecycleChange().
                $id = (string) Str::uuid7(); $approvalId = (string) Str::uuid7(); $now = now('UTC'); $expires = $now->copy()->addHours(4);
                $db->table('provider_control_operations')->insert([
                    'id' => $id, 'action_key' => 'company.lifecycle.manage', 'requester_provider_user_id' => $actor->providerUserId,
                    'approval_request_id' => null, 'idempotency_key_hash' => $keyHash, 'intent_digest' => $digest,
                    'target_tenant_id' => $intent['tenant_id'], 'status' => 'PENDING_APPROVAL',
                    'lifecycle_action' => $intent['lifecycle_action'], 'reason' => $intent['reason'],
                    'ticket_reference' => $intent['ticket_reference'], 'expires_at' => $expires,
                    'created_at' => $now, 'updated_at' => $now,
                ]);
                $db->table('provider_approval_requests')->insert([
                    'id' => $approvalId, 'operation_id' => $id, 'intent_digest' => $digest,
                    'requester_provider_user_id' => $actor->providerUserId, 'action_key' => 'company.lifecycle.manage',
                    'target_kind' => 'TENANT', 'target_id' => $intent['tenant_id'], 'reason' => $intent['reason'],
                    'ticket_reference' => $intent['ticket_reference'], 'required_approvals' => 1,
                    'expires_at' => $expires, 'status' => 'PENDING', 'created_at' => $now, 'updated_at' => $now,
                ]);
                $db->table('provider_control_operations')->where('id', $id)->update(['approval_request_id' => $approvalId]);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::PROVIDER_CONTROL_OPERATION_CREATED, $id);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::PROVIDER_APPROVAL_REQUESTED, $approvalId);
                $status = $this->applyRootBypassIfHeld($db, $actor, $id, $approvalId, 'company.lifecycle.manage');
                return ['id' => $id, 'status' => $status, 'approval_request_id' => $approvalId];
            });
    }

    public function executeLifecycleChange(ProviderContext $actor, string $operationId): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.lifecycle.manage');
        if (! Str::isUuid($operationId)) { throw ProviderAccessException::approvalUnusable(); }
        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, 'company.lifecycle.manage', 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $operationId): array {
                $this->assertProvider($db, $actor, 'company.lifecycle.manage');
                $op = $db->table('provider_control_operations')->where('id', $operationId)
                    ->where('action_key', 'company.lifecycle.manage')->lockForUpdate()->first([
                        'id', 'action_key', 'requester_provider_user_id', 'approval_request_id', 'target_tenant_id',
                        'status', 'lifecycle_action', 'intent_digest', 'expires_at',
                    ]);
                if (! $op || $op->requester_provider_user_id !== $actor->providerUserId
                    || now('UTC')->greaterThanOrEqualTo($op->expires_at)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                foreach (['app.provider_operation_id' => $op->id,
                    'app.provider_approval_id' => $op->approval_request_id,
                    'app.provider_target_tenant_id' => $op->target_tenant_id,
                    'app.provider_action' => 'company.lifecycle.manage'] as $key => $value) {
                    $db->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
                }
                if ($op->status === 'SUCCEEDED') {
                    $tenant = $db->table('tenants')->where('id', $op->target_tenant_id)->first(['id', 'status']);
                    if (! $tenant) { throw ProviderAccessException::approvalUnusable(); }
                    return ['id' => $op->id, 'status' => 'SUCCEEDED', 'tenant_id' => $tenant->id, 'company_status' => $tenant->status];
                }
                if ($op->status !== 'READY') { throw ProviderAccessException::approvalUnusable(); }
                $approval = $db->table('provider_approval_requests')->where('id', $op->approval_request_id)
                    ->lockForUpdate()->first([
                        'id', 'operation_id', 'review_revision', 'intent_digest', 'action_key', 'target_id',
                        'requester_provider_user_id', 'status', 'expires_at', 'consumed_at', 'required_approvals',
                    ]);
                $this->assertApproval($db, $approval, $op, $actor);
                $tenant = $db->table('tenants')->where('id', $op->target_tenant_id)->lockForUpdate()->first(['id', 'status']);
                $toStatus = match ($op->lifecycle_action) {
                    'SUSPEND' => 'SUSPENDED', 'RESUME' => 'ACTIVE', 'ARCHIVE' => 'ARCHIVED',
                };
                $validFrom = match ($op->lifecycle_action) {
                    'SUSPEND' => ['ACTIVE'], 'RESUME' => ['SUSPENDED'], 'ARCHIVE' => ['ACTIVE', 'SUSPENDED'],
                };
                if (! $tenant || ! in_array($tenant->status, $validFrom, true)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                $now = now('UTC');
                $updated = $db->table('tenants')->where('id', $op->target_tenant_id)->where('status', $tenant->status)
                    ->update(['status' => $toStatus, 'archived_at' => $toStatus === 'ARCHIVED' ? $now : null, 'updated_at' => $now]);
                if ($updated !== 1) { throw ProviderAccessException::approvalUnusable(); }
                $db->table('provider_approval_requests')->where('id', $approval->id)->update([
                    'consumed_at' => $now, 'consumed_operation_id' => $op->id, 'updated_at' => $now,
                ]);
                $db->table('provider_control_operations')->where('id', $op->id)->update([
                    'status' => 'SUCCEEDED', 'result_reference' => $op->target_tenant_id,
                    'completed_at' => $now, 'updated_at' => $now,
                ]);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::TENANT_LIFECYCLE_CHANGED,
                    $op->target_tenant_id, $op->target_tenant_id,
                    ['before_status' => $tenant->status, 'after_status' => $toStatus]);
                return ['id' => $op->id, 'status' => 'SUCCEEDED', 'tenant_id' => $op->target_tenant_id, 'company_status' => $toStatus];
            });
    }

    /** @param array<string, mixed> $input */
    public function editProvision(ProviderContext $actor, string $operationId, array $input): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.provision');
        if (! Str::isUuid($operationId) || ! is_int($input['expected_revision'] ?? null)
            || $input['expected_revision'] < 1) {
            throw ProviderAccessException::approvalUnusable();
        }
        $reasonInput = $input['edit_reason'] ?? null;
        if ($reasonInput !== null && ! is_string($reasonInput)) {
            throw ValidationException::withMessages(['edit_reason' => ['The edit reason is invalid.']]);
        }
        $rawReason = $reasonInput ?? '';
        if (! mb_check_encoding($rawReason, 'UTF-8')) {
            throw ValidationException::withMessages(['edit_reason' => ['The edit reason is invalid.']]);
        }
        $reason = preg_replace('/^\s+|\s+$/u', '', $rawReason);
        if (! is_string($reason)
            || ($reason !== '' && preg_match('/[\x00-\x1F\x7F]/u', $rawReason) !== 0)) {
            throw ValidationException::withMessages(['edit_reason' => ['The edit reason is invalid.']]);
        }
        if (mb_strlen($reason) > 500) {
            throw ValidationException::withMessages(['edit_reason' => ['The edit reason is invalid.']]);
        }
        $display = trim((string) $input['display_name']);
        $slug = strtolower(trim((string) $input['slug']));
        $adminName = trim((string) $input['first_admin_display_name']);
        $timezone = (string) $input['timezone'];
        try {
            $email = $this->emails->normalize((string) $input['first_admin_email']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['first_admin_email' => ['The first administrator email is invalid.']]);
        }
        if ($display === '' || mb_strlen($display) > 160 || $adminName === '' || mb_strlen($adminName) > 160
            || preg_match('/[\x00-\x1F\x7F]/u', $adminName) === 1
            || ! preg_match('/^[a-z0-9]+(?:-[a-z0-9]+)*$/D', $slug) || mb_strlen($slug) > 100
            || ! filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 254
            || ! in_array($timezone, timezone_identifiers_list(), true)) {
            throw ValidationException::withMessages(['operation' => ['The provisioning edit is invalid.']]);
        }
        $fields = ['display_name' => $display, 'canonical_slug' => $slug, 'timezone' => $timezone,
            'founder_email' => $email, 'first_admin_display_name' => $adminName];
        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, 'company.provision', 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $operationId, $input, $fields, $reason): array {
                $this->assertProvider($db, $actor, 'company.provision');
                $op = $db->table('provider_control_operations')->where('id', $operationId)->lockForUpdate()->first([
                    'id', 'action_key', 'requester_provider_user_id', 'status', 'completed_at', 'expires_at',
                    'approval_request_id', 'current_revision', 'target_tenant_id', 'display_name',
                    'canonical_slug', 'timezone', 'founder_email', 'first_admin_display_name',
                    'intent_digest', 'reason', 'ticket_reference',
                ]);
                if (! $op || $op->action_key !== 'company.provision'
                    || $op->requester_provider_user_id !== $actor->providerUserId
                    || $op->status !== 'PENDING_APPROVAL' || $op->completed_at !== null
                    || now('UTC')->greaterThanOrEqualTo($op->expires_at)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                $approval = $db->table('provider_approval_requests')->where('id', $op->approval_request_id)
                    ->lockForUpdate()->first([
                        'id', 'operation_id', 'requester_provider_user_id', 'status', 'consumed_at',
                        'intent_digest', 'review_revision', 'expires_at',
                    ]);
                if (! $approval || $approval->operation_id !== $op->id
                    || $approval->requester_provider_user_id !== $actor->providerUserId
                    || $approval->status !== 'PENDING' || $approval->consumed_at !== null
                    || $approval->intent_digest !== $op->intent_digest
                    || (int) $approval->review_revision !== (int) $op->current_revision
                    || now('UTC')->greaterThanOrEqualTo($approval->expires_at)
                    || $db->table('provider_approval_decisions')->where('approval_request_id', $approval->id)->exists()) {
                    throw ProviderAccessException::approvalUnusable();
                }
                if ((int) $op->current_revision !== $input['expected_revision']) {
                    throw new ProviderAccessException('PROVIDER_REVISION_CONFLICT', 409);
                }
                $changed = [];
                foreach ($fields as $key => $value) {
                    if ((string) $op->{$key} !== $value) { $changed[] = $key; }
                }
                if ($changed === []) {
                    return $this->safeProvisionPayload($op);
                }
                try {
                    $reasonCiphertext = $reason === '' ? null : Crypt::encryptString($reason);
                } catch (Throwable) {
                    throw new ProviderAccessException('PROVIDER_REVISION_HISTORY_UNAVAILABLE', 503);
                }
                if (in_array('canonical_slug', $changed, true)) {
                    if ($db->table('provider_control_operations')->where('id', '<>', $op->id)
                        ->where('canonical_slug', $fields['canonical_slug'])
                        ->whereIn('status', ['PENDING_APPROVAL', 'READY'])->exists()) {
                        throw ValidationException::withMessages(['slug' => ['The company slug is already reserved.']]);
                    }
                    $this->assertAvailableHostname($fields['canonical_slug']);
                }
                $intent = ['action' => 'company.provision', 'display_name' => $fields['display_name'],
                    'slug' => $fields['canonical_slug'], 'timezone' => $fields['timezone'],
                    'founder_email' => $fields['founder_email'],
                    'first_admin_display_name' => $fields['first_admin_display_name'],
                    'reason' => $op->reason, 'ticket_reference' => $op->ticket_reference,
                    'tenant_id' => $op->target_tenant_id];
                $digest = hash('sha256', json_encode($intent, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
                $revision = (int) $op->current_revision + 1;
                $now = now('UTC');
                $db->table('provider_control_operations')->where('id', $op->id)->update($fields + [
                    'intent_digest' => $digest, 'current_revision' => $revision, 'updated_at' => $now]);
                $db->table('provider_approval_requests')->where('id', $approval->id)->update([
                    'intent_digest' => $digest, 'review_revision' => $revision, 'updated_at' => $now]);
                $db->table('provider_provision_revisions')->insert([
                    'operation_id' => $op->id, 'revision' => $revision, 'intent_digest' => $digest,
                    'requester_provider_user_id' => $actor->providerUserId,
                    'changed_fields' => json_encode($changed, JSON_THROW_ON_ERROR),
                    'edit_reason_ciphertext' => $reasonCiphertext, 'created_at' => $now]);
                $this->audit->appendProviderControlMutation($db, $actor,
                    AuditEventType::PROVIDER_CONTROL_OPERATION_EDITED, $op->id, null, [
                        'before_digest' => $op->intent_digest, 'after_digest' => $digest,
                        'revision' => $revision, 'changed_fields' => $changed]);
                $op = $db->table('provider_control_operations')->where('id', $op->id)->first([
                    'id', 'approval_request_id', 'status', 'current_revision', 'intent_digest', 'display_name',
                    'canonical_slug', 'timezone', 'founder_email', 'first_admin_display_name', 'expires_at',
                ]);
                return $this->safeProvisionPayload($op);
            });
    }

    private function safeProvisionPayload(object $op): array
    {
        return ['id' => $op->id, 'approval_request_id' => $op->approval_request_id,
            'status' => $op->status, 'revision' => (int) $op->current_revision,
            'intent_digest' => $op->intent_digest, 'display_name' => $op->display_name,
            'slug' => $op->canonical_slug, 'timezone' => $op->timezone,
            'first_admin_email' => $op->founder_email,
            'first_admin_display_name' => $op->first_admin_display_name,
            'expires_at' => $op->expires_at];
    }

    /** @return array{operation_id:string,revisions:list<array<string,mixed>>,next_before_revision:?int} */
    public function provisionRevisionHistory(ProviderContext $actor, string $operationId,
        int $limit = 50, ?int $beforeRevision = null): array
    {
        $this->authorization->assertStepUp($actor);
        if (! Str::isUuid($operationId) || $limit < 1 || $limit > 50
            || ($beforeRevision !== null && $beforeRevision < 1)) {
            throw ProviderAccessException::approvalUnusable();
        }

        $capabilities = $this->authorization->capabilities($actor);
        if (! in_array('company.provision', $capabilities, true)
            && ! in_array('provider.approval.review', $capabilities, true)) {
            throw ProviderAccessException::denied();
        }

        $db = DB::connection('pgsql_provider_control');
        $operation = $db->table('provider_control_operations')->where('id', $operationId)
            ->first(['id', 'action_key', 'requester_provider_user_id']);
        if (! $operation || $operation->action_key !== 'company.provision') {
            throw ProviderAccessException::approvalUnusable();
        }

        $isOwner = $operation->requester_provider_user_id === $actor->providerUserId;
        if ($isOwner) {
            if (! in_array('company.provision', $capabilities, true)) {
                throw ProviderAccessException::approvalUnusable();
            }
            $capability = 'company.provision';
        } else {
            if (! in_array('provider.approval.review', $capabilities, true)) {
                throw ProviderAccessException::approvalUnusable();
            }
            $capability = 'provider.approval.review';
        }

        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, $capability, 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $operationId, $operation, $isOwner,
                $capability, $limit, $beforeRevision): array {
                $current = $db->table('provider_control_operations')->where('id', $operationId)
                    ->first(['id', 'action_key', 'requester_provider_user_id']);
                if (! $current || $current->action_key !== 'company.provision'
                    || $current->requester_provider_user_id !== $operation->requester_provider_user_id
                    || ($isOwner && $current->requester_provider_user_id !== $actor->providerUserId)
                    || (! $isOwner && ($capability !== 'provider.approval.review'
                        || $current->requester_provider_user_id === $actor->providerUserId))) {
                    throw ProviderAccessException::approvalUnusable();
                }

                $query = $db->table('provider_provision_revisions')->where('operation_id', $operationId);
                if ($beforeRevision !== null) {
                    $query->where('revision', '<', $beforeRevision);
                }
                $rows = $query->orderByDesc('revision')->limit($limit + 1)
                    ->get(['operation_id', 'revision', 'requester_provider_user_id', 'changed_fields',
                        'created_at', 'edit_reason_ciphertext']);
                $hasMore = $rows->count() > $limit;
                $rows = $rows->take($limit);
                if ($beforeRevision === null && $rows->isEmpty()) {
                    throw ProviderAccessException::approvalUnusable();
                }

                $revisions = [];
                foreach ($rows as $row) {
                    $changedFields = json_decode((string) $row->changed_fields, true);
                    if (! is_array($changedFields) || ! array_is_list($changedFields)) {
                        throw new ProviderAccessException('PROVIDER_REVISION_HISTORY_UNAVAILABLE', 503);
                    }
                    try {
                        $editReason = $row->edit_reason_ciphertext === null
                            ? null : Crypt::decryptString($row->edit_reason_ciphertext);
                    } catch (Throwable) {
                        throw new ProviderAccessException('PROVIDER_REVISION_HISTORY_UNAVAILABLE', 503);
                    }
                    $createdAt = new \DateTimeImmutable((string) $row->created_at, new \DateTimeZone('UTC'));
                    $revisions[] = [
                        'revision' => (int) $row->revision,
                        'created_at' => $createdAt->setTimezone(new \DateTimeZone('UTC'))->format(DATE_ATOM),
                        'actor_provider_user_id' => $row->requester_provider_user_id,
                        'changed_fields' => $changedFields,
                        'edit_reason' => $editReason,
                    ];
                }
                $revisions = array_reverse($revisions);
                $next = $hasMore && $revisions !== [] ? $revisions[0]['revision'] : null;

                return ['operation_id' => $operationId, 'revisions' => $revisions,
                    'next_before_revision' => $next];
            }, $operationId, null, null, 'company.provision');
    }

    private function assertAvailableHostname(string $slug): void
    {
        try {
            $host = CanonicalTenantHost::forSlug($slug,
                config('tenancy.base_domain'), (string) config('app.env', 'production'),
                (bool) config('tenancy.allow_localhost_base_domain', false),
                config('tenancy.local_test_base_domain'));
            $this->hostResolver->resolve($host->value());
        } catch (InvalidArgumentException $exception) {
            if ($exception->getMessage() === 'No active tenant host mapping is available.') {
                return;
            }
            throw ValidationException::withMessages(['slug' => ['The company slug cannot be validated.']]);
        }
        throw ValidationException::withMessages(['slug' => ['The company slug is already reserved.']]);
    }

    public function review(ProviderContext $actor, string $approvalId, string $decision, string $reason,
        string $ticket, ?int $expectedRevision = null): string
    {
        $this->authorization->assertStepUp($actor);
        if (! Str::isUuid($approvalId) || ! in_array($decision, ['APPROVE', 'REJECT', 'REVOKE'], true)
            || trim($reason) === '' || mb_strlen(trim($reason)) > 500
            || ! preg_match('/^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,99}$/D', trim($ticket))) {
            throw ProviderAccessException::approvalUnusable();
        }
        $action = DB::connection('pgsql_provider')->table('provider_approval_requests')
            ->where('id', $approvalId)->value('action_key');
        $ownerProvisionRevoke = $decision === 'REVOKE' && $action === 'company.provision';
        $capability = $ownerProvisionRevoke ? 'company.provision' : 'provider.approval.review';
        $this->authorization->assertCapability($actor, $capability);
        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, $capability, 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $approvalId, $decision, $reason,
                $ticket, $expectedRevision, $ownerProvisionRevoke, $capability): string {
                $this->assertProvider($db, $actor, $capability);
                $identity = $db->table('provider_approval_requests')->where('id', $approvalId)
                    ->first(['operation_id']);
                if (! $identity || ! $identity->operation_id) {
                    throw ProviderAccessException::approvalUnusable();
                }
                $op = $db->table('provider_control_operations')->where('id', $identity->operation_id)
                    ->whereIn('action_key', ['company.provision', 'company.lifecycle.manage'])
                    ->lockForUpdate()->first([
                        'id', 'action_key', 'status', 'expires_at', 'intent_digest', 'current_revision',
                    ]);
                $approval = $db->table('provider_approval_requests')->where('id', $approvalId)
                    ->whereIn('action_key', ['company.provision', 'company.lifecycle.manage'])
                    ->lockForUpdate()->first([
                        'operation_id', 'requester_provider_user_id', 'action_key', 'target_kind', 'status', 'consumed_at',
                        'expires_at', 'intent_digest', 'review_revision',
                    ]);
                $isRevoke = $decision === 'REVOKE';
                $ownershipValid = $isRevoke
                    ? $approval?->requester_provider_user_id === $actor->providerUserId
                    : $approval?->requester_provider_user_id !== $actor->providerUserId;
                $provision = $op?->action_key === 'company.provision';
                $lifecycle = $op?->action_key === 'company.lifecycle.manage';
                $statusValid = ($provision && $approval?->action_key === 'company.provision'
                        && $approval?->target_kind === 'PROVISIONING_INTENT'
                        && $approval?->status === 'PENDING' && $op?->status === 'PENDING_APPROVAL')
                    || ($lifecycle && $approval?->action_key === 'company.lifecycle.manage'
                        && $approval?->target_kind === 'TENANT'
                        && $approval?->status === 'PENDING' && $op?->status === 'PENDING_APPROVAL');
                if (! $op || ! $approval || $approval->operation_id !== $op->id
                    || $approval->action_key !== $op->action_key
                    || $ownerProvisionRevoke !== ($isRevoke && $provision)
                    || ! $ownershipValid || ! $statusValid
                    || $approval->consumed_at !== null || now('UTC')->greaterThanOrEqualTo($approval->expires_at)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                if ($provision && (now('UTC')->greaterThanOrEqualTo($op->expires_at)
                    || $approval->intent_digest !== $op->intent_digest
                    || (int) $approval->review_revision !== (int) $op->current_revision
                    || $db->table('provider_approval_decisions')->where('approval_request_id', $approvalId)->exists())) {
                    throw ProviderAccessException::approvalUnusable();
                }
                if ($lifecycle && (now('UTC')->greaterThanOrEqualTo($op->expires_at)
                    || $approval->intent_digest !== $op->intent_digest
                    || $db->table('provider_approval_decisions')->where('approval_request_id', $approvalId)->exists())) {
                    throw ProviderAccessException::approvalUnusable();
                }
                if ($provision && ! $isRevoke) {
                    if ($expectedRevision === null || $expectedRevision < 1) {
                        throw ProviderAccessException::approvalUnusable();
                    }
                    if ($expectedRevision !== (int) $op->current_revision) {
                        throw new ProviderAccessException('PROVIDER_REVISION_CONFLICT', 409);
                    }
                }
                $db->table('provider_approval_decisions')->insert([
                    'id' => (string) Str::uuid7(), 'approval_request_id' => $approvalId,
                    'approver_provider_user_id' => $actor->providerUserId, 'decision' => $decision,
                    'decision_revision' => $provision ? (int) $op->current_revision : null,
                    'reason' => trim($reason), 'ticket_reference' => trim($ticket), 'decided_at' => now('UTC'),
                ]);
                $status = $decision === 'REJECT' ? 'REJECTED' : ($decision === 'REVOKE' ? 'REVOKED' : 'APPROVED');
                $db->table('provider_approval_requests')->where('id', $approvalId)->update(['status' => $status, 'updated_at' => now('UTC')]);
                if ($decision === 'APPROVE') {
                    $db->table('provider_control_operations')->where('id', $approval->operation_id)
                        ->where('status', 'PENDING_APPROVAL')->update(['status' => 'READY', 'updated_at' => now('UTC')]);
                } elseif ($decision === 'REVOKE') {
                    $db->table('provider_control_operations')->where('id', $approval->operation_id)
                        ->whereIn('status', $provision ? ['PENDING_APPROVAL'] : ['PENDING_APPROVAL', 'READY'])
                        ->update(['status' => 'CANCELLED', 'updated_at' => now('UTC')]);
                }
                $event = match ($decision) {
                    'APPROVE' => AuditEventType::PROVIDER_APPROVAL_APPROVED,
                    'REJECT' => AuditEventType::PROVIDER_APPROVAL_REJECTED,
                    'REVOKE' => AuditEventType::PROVIDER_APPROVAL_REVOKED,
                };
                $this->audit->appendProviderControlMutation($db, $actor, $event, $approvalId);
                return $status;
            });
    }

    public function executeProvision(ProviderContext $actor, string $operationId, string $initialPassword): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.provision');
        if (! Str::isUuid($operationId)) { throw ProviderAccessException::approvalUnusable(); }
        try {
            return $this->context->run($actor->providerUserId, $actor->authVersion,
                (int) $actor->stepUpVerifiedAt, 'company.provision', 'PROVIDER_CONTROL',
                function (ConnectionInterface $db) use ($actor, $operationId, $initialPassword): array {
                $this->assertProvider($db, $actor, 'company.provision');
                $op = $db->table('provider_control_operations')->where('id', $operationId)->lockForUpdate()->first([
                    'id', 'requester_provider_user_id', 'action_key', 'expires_at', 'approval_request_id',
                    'target_tenant_id', 'status', 'first_admin_display_name', 'display_name', 'canonical_slug',
                    'timezone', 'founder_email', 'intent_digest', 'current_revision',
                ]);
                if (! $op || $op->requester_provider_user_id !== $actor->providerUserId
                    || $op->action_key !== 'company.provision' || now('UTC')->greaterThanOrEqualTo($op->expires_at)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                foreach (['app.provider_operation_id' => $op->id,
                    'app.provider_approval_id' => $op->approval_request_id,
                    'app.provider_target_tenant_id' => $op->target_tenant_id,
                    'app.provider_action' => $op->action_key] as $key => $value) {
                    $db->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
                }
                if ($op->status === 'SUCCEEDED') {
                    $result = $db->table('tenants as tenant')
                        ->join('tenant_hostnames as host', 'host.tenant_id', '=', 'tenant.id')
                        ->where('tenant.id', $op->target_tenant_id)->where('tenant.status', 'ACTIVE')
                        ->first(['tenant.id', 'tenant.slug', 'host.hostname']);
                    if (! $result) { throw ProviderAccessException::approvalUnusable(); }
                    return ['id' => $op->id, 'status' => 'SUCCEEDED', 'tenant_id' => $result->id,
                        'slug' => $result->slug, 'hostname' => $result->hostname];
                }
                if ($op->status !== 'READY') { throw ProviderAccessException::approvalUnusable(); }
                if (! is_string($op->first_admin_display_name) || trim($op->first_admin_display_name) === '') {
                    throw ProviderAccessException::approvalUnusable();
                }
                $approval = $db->table('provider_approval_requests')->where('id', $op->approval_request_id)
                    ->lockForUpdate()->first([
                        'id', 'operation_id', 'review_revision', 'intent_digest', 'action_key', 'target_id',
                        'requester_provider_user_id', 'status', 'expires_at', 'consumed_at', 'required_approvals',
                    ]);
                $this->assertApproval($db, $approval, $op, $actor);
                $now = now('UTC');
                $db->table('tenants')->insert([
                    'id' => $op->target_tenant_id, 'display_name' => $op->display_name,
                    'legal_name' => null, 'slug' => $op->canonical_slug,
                    'status' => 'PROVISIONING', 'timezone' => $op->timezone,
                    'default_locale' => 'en', 'archived_at' => null, 'created_at' => $now, 'updated_at' => $now,
                ]);
                $this->hostnames->register($db, $op->target_tenant_id, $op->canonical_slug);

                $staff = $this->staffAccounts->build($op->target_tenant_id, $op->founder_email,
                    $op->first_admin_display_name, $initialPassword);
                $db->table('tenant_staff_users')->insert($staff);
                $membershipId = (string) Str::uuid7();
                $db->table('tenant_staff_memberships')->insert([
                    'id' => $membershipId, 'tenant_id' => $op->target_tenant_id,
                    'staff_user_id' => $staff['id'], 'status' => 'ACTIVE', 'authorization_version' => 1,
                    'joined_at' => $now, 'created_by_membership_id' => null,
                    'created_by_provider_operation_id' => $op->id, 'created_at' => $now, 'updated_at' => $now,
                ]);

                $roleId = $this->createFirstAdminRole($db, $op->target_tenant_id, $now);
                $db->table('tenant_staff_membership_roles')->insert([
                    'id' => (string) Str::uuid7(), 'tenant_id' => $op->target_tenant_id,
                    'membership_id' => $membershipId, 'role_id' => $roleId,
                    'assigned_by_membership_id' => null, 'assigned_by_provider_operation_id' => $op->id,
                    'assigned_at' => $now, 'revoked_at' => null, 'revoked_by_membership_id' => null,
                    'created_at' => $now, 'updated_at' => $now,
                ]);

                if (! $this->firstAdminCanAdminister($db, $op->target_tenant_id, $staff['id'], $membershipId)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                $db->table('tenant_staff_security_events')->insert([
                    'id' => (string) Str::uuid7(), 'occurred_at' => $now,
                    'tenant_id' => $op->target_tenant_id, 'event_type' => 'tenant_staff.created',
                    'outcome' => 'SUCCESS', 'request_id' => $actor->requestId,
                    'actor_membership_id' => null, 'provider_operation_id' => $op->id,
                    'target_staff_user_id' => $staff['id'], 'metadata' => '{}',
                ]);

                $activated = $db->table('tenants')->where('id', $op->target_tenant_id)
                    ->where('status', 'PROVISIONING')->update(['status' => 'ACTIVE', 'updated_at' => $now]);
                if ($activated !== 1) { throw ProviderAccessException::approvalUnusable(); }
                $db->table('provider_approval_requests')->where('id', $approval->id)->update([
                    'consumed_at' => $now, 'consumed_operation_id' => $op->id, 'updated_at' => $now,
                ]);
                $db->table('provider_control_operations')->where('id', $op->id)->update([
                    'status' => 'SUCCEEDED', 'result_reference' => $op->target_tenant_id,
                    'completed_at' => $now, 'updated_at' => $now,
                ]);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::TENANT_PROVISIONING_EXECUTED,
                    $op->target_tenant_id, $op->target_tenant_id);
                $hostname = $db->table('tenant_hostnames')->where('tenant_id', $op->target_tenant_id)->value('hostname');
                return ['id' => $op->id, 'status' => 'SUCCEEDED', 'tenant_id' => $op->target_tenant_id,
                    'slug' => $op->canonical_slug, 'hostname' => $hostname];
                }, $operationId, null, null, 'company.provision');
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages(['initial_password' => ['The initial password does not meet the account requirements.']]);
        } catch (DomainException) {
            throw ValidationException::withMessages(['slug' => ['The company hostname could not be reserved for this operation.']]);
        } catch (QueryException $exception) {
            $previous = $exception->getPrevious();
            $sqlState = is_object($previous) && isset($previous->errorInfo[0])
                ? (string) $previous->errorInfo[0] : (string) $exception->getCode();
            if ($sqlState === '23505') {
                throw ValidationException::withMessages(['slug' => ['The company slug or hostname is already reserved.']]);
            }

            $safeSqlState = preg_match('/\A[A-Z0-9]{5}\z/D', $sqlState) === 1 ? $sqlState : 'UNKNOWN';
            $failureCategory = match ($safeSqlState) {
                '42501' => 'POSTGRES_PRIVILEGE_OR_RLS_DENIAL',
                '23503' => 'POSTGRES_FOREIGN_KEY_FAILURE',
                '23502' => 'POSTGRES_NOT_NULL_FAILURE',
                '40001' => 'POSTGRES_SERIALIZATION_FAILURE',
                '40P01' => 'POSTGRES_DEADLOCK',
                'UNKNOWN' => 'POSTGRES_QUERY_FAILURE',
                default => 'POSTGRES_QUERY_FAILURE',
            };

            logger()->error('Provider provisioning persistence failure; details sanitized.', [
                'request_id' => $actor->requestId,
                'operation_id' => $operationId,
                'operation_status' => 'EXECUTE_FAILED',
                'exception_class' => QueryException::class,
                'sqlstate' => $safeSqlState,
                'failure_category' => $failureCategory,
                'source' => 'ProviderControlOperationService::executeProvision',
            ]);

            throw new RuntimeException('Provider provisioning persistence failed.');
        }
    }

    private function createFirstAdminRole(ConnectionInterface $db, string $tenantId, mixed $now): string
    {
        $template = $db->table('role_templates')->where('code', 'company_admin')
            ->where('version', 1)->where('status', 'ACTIVE')
            ->first(['id', 'code', 'version', 'status']);
        if (! $template) { throw ProviderAccessException::approvalUnusable(); }
        $templateGrants = $db->table('role_template_permissions')->where('template_id', $template->id)
            ->get(['permission_key', 'scope']);
        $hasAdminGrant = $templateGrants->contains(static fn ($grant): bool =>
            $grant->permission_key === 'company.administer' && $grant->scope === 'ALL_TENANT');
        $catalogAllowsAdmin = $db->table('permissions')->where('key', 'company.administer')
            ->where('status', 'ACTIVE')->where('scopeable', true)
            ->whereJsonContains('allowed_scopes', 'ALL_TENANT')
            ->value('key') === 'company.administer';
        if (! $hasAdminGrant || ! $catalogAllowsAdmin) { throw ProviderAccessException::approvalUnusable(); }

        $roleId = (string) Str::uuid7();
        $db->table('roles')->insert([
            'id' => $roleId, 'tenant_id' => $tenantId, 'display_name' => 'Company Admin',
            'normalized_name' => 'company_admin', 'status' => 'ACTIVE', 'source_template_id' => $template->id,
            'version' => 1, 'archived_at' => null, 'created_at' => $now, 'updated_at' => $now,
        ]);
        foreach ($templateGrants as $grant) {
            $db->table('role_permissions')->insert([
                'tenant_id' => $tenantId, 'role_id' => $roleId,
                'permission_key' => $grant->permission_key, 'scope' => $grant->scope,
            ]);
        }
        return $roleId;
    }

    private function firstAdminCanAdminister(ConnectionInterface $db, string $tenantId,
        string $staffUserId, string $membershipId): bool
    {
        $hasActiveAssignment = $db->table('tenant_staff_memberships as membership')
            ->join('tenant_staff_users as staff', function ($join): void {
                $join->on('staff.tenant_id', '=', 'membership.tenant_id')
                    ->on('staff.id', '=', 'membership.staff_user_id');
            })
            ->join('tenant_staff_membership_roles as assignment', function ($join): void {
                $join->on('assignment.tenant_id', '=', 'membership.tenant_id')
                    ->on('assignment.membership_id', '=', 'membership.id');
            })
            ->join('roles as role', function ($join): void {
                $join->on('role.tenant_id', '=', 'assignment.tenant_id')
                    ->on('role.id', '=', 'assignment.role_id');
            })
            ->where('membership.tenant_id', $tenantId)->where('membership.id', $membershipId)
            ->where('membership.staff_user_id', $staffUserId)->where('membership.status', 'ACTIVE')
            ->where('staff.status', 'ACTIVE')->where('role.status', 'ACTIVE')->whereNull('role.archived_at')
            ->whereNull('assignment.revoked_at')->select('membership.id')->exists();
        if (! $hasActiveAssignment) {
            return false;
        }

        $roleId = $db->table('tenant_staff_membership_roles')->where('tenant_id', $tenantId)
            ->where('membership_id', $membershipId)->whereNull('revoked_at')->value('role_id');
        if (! is_string($roleId)) {
            return false;
        }
        $roleGrants = $db->table('role_permissions')->where('tenant_id', $tenantId)->where('role_id', $roleId)
            ->get(['permission_key', 'scope'])->map(static fn ($grant): array => [
                'permission_key' => $grant->permission_key,
                'scope' => $grant->scope,
            ])->all();
        $keys = array_values(array_unique(array_column($roleGrants, 'permission_key')));
        $catalog = $db->table('permissions')->whereIn('key', $keys)
            ->get(['key', 'status', 'scopeable', 'allowed_scopes', 'delegable'])
            ->mapWithKeys(static fn ($permission): array => [$permission->key => [
                'status' => $permission->status,
                'scopeable' => (bool) $permission->scopeable,
                'allowed_scopes' => is_array($permission->allowed_scopes)
                    ? $permission->allowed_scopes
                    : json_decode((string) $permission->allowed_scopes, true, flags: JSON_THROW_ON_ERROR),
                'delegable' => (bool) $permission->delegable,
            ]])->all();
        $effective = $this->effectivePermissions->resolve($roleGrants, [], $catalog);

        return $effective !== null
            && in_array('ALL_TENANT', $effective['company.administer'] ?? [], true);
    }

    public function executeRecovery(ProviderContext $actor, string $operationId): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.recover');
        if (! Str::isUuid($operationId)) { throw ProviderAccessException::approvalUnusable(); }
        return $this->context->run($actor->providerUserId, $actor->authVersion,
            (int) $actor->stepUpVerifiedAt, 'company.recover', 'PROVIDER_CONTROL',
            function (ConnectionInterface $db) use ($actor, $operationId): array {
                $this->assertProvider($db, $actor, 'company.recover');
                $op0 = $db->table('provider_control_operations')->where('id', $operationId)->first();
                if (! $op0 || $op0->requester_provider_user_id !== $actor->providerUserId
                    || $op0->action_key !== 'company.recover') { throw ProviderAccessException::approvalUnusable(); }
                if ($op0->status === 'SUCCEEDED') { return ['id' => $op0->id, 'status' => 'SUCCEEDED', 'tenant_id' => $op0->target_tenant_id]; }
                if ($op0->status !== 'READY' || now('UTC')->greaterThanOrEqualTo($op0->expires_at)) { throw ProviderAccessException::approvalUnusable(); }
                foreach (['app.provider_operation_id' => $op0->id, 'app.provider_approval_id' => $op0->approval_request_id,
                    'app.provider_target_tenant_id' => $op0->target_tenant_id, 'app.provider_action' => $op0->action_key] as $key => $value) {
                    $db->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
                }
                // Lock target tenant before all target memberships/roles: this serializes recovery and last-admin writes.
                $tenant = $db->table('tenants')->where('id', $op0->target_tenant_id)->lockForUpdate()->first();
                $op = $db->table('provider_control_operations')->where('id', $operationId)->lockForUpdate()->first();
                $approval = $db->table('provider_approval_requests')->where('id', $op->approval_request_id)->lockForUpdate()->first();
                $this->assertApproval($db, $approval, $op, $actor);
                if (! $tenant || ! in_array($tenant->status, ['ACTIVE', 'SUSPENDED'], true)) {
                    throw ProviderAccessException::approvalUnusable();
                }
                $successor = $db->selectOne('SELECT * FROM app_provider_control_lock_successor(?, ?)',
                    [$op->id, $op->successor_user_id]);
                if (! $successor || $successor->status !== 'ACTIVE' || $successor->email_verified_at === null
                    || $successor->id === $op->requester_provider_user_id) { throw ProviderAccessException::approvalUnusable(); }
                if ($db->table('tenant_memberships')->where('user_id', $successor->id)->where('status', 'ACTIVE')
                    ->where('tenant_id', '<>', $tenant->id)->exists()) { throw ProviderAccessException::approvalUnusable(); }
                $membership = $db->table('tenant_memberships')->where('tenant_id', $tenant->id)
                    ->where('user_id', $successor->id)->lockForUpdate()->first();
                if (! $membership) {
                    $membershipId = (string) Str::uuid7();
                    $db->table('tenant_memberships')->insert(['id' => $membershipId, 'tenant_id' => $tenant->id,
                        'user_id' => $successor->id, 'status' => 'ACTIVE', 'authorization_version' => 1,
                        'joined_at' => now('UTC'), 'created_at' => now('UTC'), 'updated_at' => now('UTC')]);
                } else {
                    $membershipId = $membership->id;
                    if ($membership->status === 'SUSPENDED') {
                        $db->table('tenant_memberships')->where('id', $membershipId)->update([
                            'status' => 'ACTIVE', 'authorization_version' => $membership->authorization_version + 1,
                            'updated_at' => now('UTC')]);
                    }
                }
                $template = $db->table('role_templates')->where('code', 'company_admin')->where('version', 1)->where('status', 'ACTIVE')->first();
                if (! $template) { throw ProviderAccessException::approvalUnusable(); }
                $role = $db->table('roles')->where('tenant_id', $tenant->id)->where('normalized_name', 'company_admin')->lockForUpdate()->first();
                if (! $role) {
                    $roleId = (string) Str::uuid7();
                    $db->table('roles')->insert(['id' => $roleId, 'tenant_id' => $tenant->id,
                        'display_name' => 'Company Admin', 'normalized_name' => 'company_admin', 'status' => 'ACTIVE',
                        'source_template_id' => $template->id, 'version' => 1, 'archived_at' => null,
                        'created_at' => now('UTC'), 'updated_at' => now('UTC')]);
                    foreach ($db->table('role_template_permissions')->where('template_id', $template->id)->get() as $grant) {
                        $db->table('role_permissions')->insert(['tenant_id' => $tenant->id, 'role_id' => $roleId,
                            'permission_key' => $grant->permission_key, 'scope' => $grant->scope]);
                    }
                } else { $roleId = $role->id; }
                $db->table('membership_roles')->insertOrIgnore(['tenant_id' => $tenant->id, 'membership_id' => $membershipId,
                    'role_id' => $roleId, 'assigned_by_user_id' => null, 'assigned_at' => now('UTC')]);
                $admin = $db->table('tenant_memberships as m')->join('membership_roles as mr', function ($join): void {
                        $join->on('mr.tenant_id', '=', 'm.tenant_id')->on('mr.membership_id', '=', 'm.id');
                    })->join('roles as r', function ($join): void { $join->on('r.tenant_id', '=', 'mr.tenant_id')->on('r.id', '=', 'mr.role_id'); })
                    ->join('role_permissions as rp', function ($join): void { $join->on('rp.tenant_id', '=', 'r.tenant_id')->on('rp.role_id', '=', 'r.id'); })
                    ->where('m.tenant_id', $tenant->id)->where('m.status', 'ACTIVE')->where('r.status', 'ACTIVE')
                    ->where('rp.permission_key', 'company.administer')->where('rp.scope', 'ALL_TENANT')->count() > 0;
                if (! $admin) { throw ProviderAccessException::approvalUnusable(); }
                $compromisedId = $op->compromised_membership_id;
                if ($op->recovery_mode === 'REPLACE_ADMIN') {
                    $bad = $db->table('tenant_memberships')->where('tenant_id', $tenant->id)->where('id', $compromisedId)->lockForUpdate()->first();
                    if (! $bad || $bad->user_id === $successor->id || $bad->status !== 'ACTIVE') { throw ProviderAccessException::approvalUnusable(); }
                    $db->table('tenant_memberships')->where('id', $bad->id)->update([
                        'status' => 'SUSPENDED', 'authorization_version' => $bad->authorization_version + 1,
                        'updated_at' => now('UTC')]);
                }
                $now = now('UTC');
                $db->table('provider_approval_requests')->where('id', $approval->id)->update([
                    'consumed_at' => $now, 'consumed_operation_id' => $op->id, 'updated_at' => $now]);
                $db->table('provider_control_operations')->where('id', $op->id)->update([
                    'status' => 'SUCCEEDED', 'result_reference' => $tenant->id, 'completed_at' => $now, 'updated_at' => $now]);
                $this->audit->appendProviderControlMutation($db, $actor, AuditEventType::TENANT_RECOVERY_EXECUTED,
                    $tenant->id, $tenant->id, [
                    'successor_user_id' => $successor->id, 'successor_membership_id' => $membershipId,
                    'compromised_membership_id' => $compromisedId]);
                return ['id' => $op->id, 'status' => 'SUCCEEDED', 'tenant_id' => $tenant->id];
            }, $operationId, null, null, 'company.recover');
    }

    public function approveFounder(string $invitationId, string $token, ?string $authenticatedUserId,
        ?string $password, ?string $passwordConfirmation): array
    {
        if (! Str::isUuid($invitationId) || strlen($token) < 40 || strlen($token) > 128) {
            throw ProviderAccessException::approvalUnusable();
        }
        $db = \Illuminate\Support\Facades\DB::connection('pgsql_provider_control');
        // New-account INSERT is delegated to a separate onboarding role; activation is a retryable later step.
        $invite = $db->table('tenant_founder_invitations')->where('id', $invitationId)->first();
        if (! $invite || $invite->revoked_at !== null || $invite->accepted_at !== null
            || now('UTC')->greaterThanOrEqualTo($invite->expires_at)
            || ! hash_equals($invite->token_hash, hash('sha256', $token))) {
            throw ProviderAccessException::approvalUnusable();
        }
        $userId = $authenticatedUserId;
        if ($userId === null) {
            if (! $password || $password !== $passwordConfirmation || mb_strlen($password) < 12 || mb_strlen($password) > 1024) {
                throw ValidationException::withMessages(['credentials' => ['The invitation cannot be accepted.']]);
            }
            $existing = \Illuminate\Support\Facades\DB::connection()->table('users')
                ->where('email', $invite->email_canonical)->first(['id']);
            if ($existing) { throw ProviderAccessException::approvalUnusable(); }
            $userId = (string) Str::uuid7();
            \Illuminate\Support\Facades\DB::connection('pgsql_onboarding')->table('users')->insert([
                'id' => $userId, 'email' => $invite->email_canonical,
                'password' => \Illuminate\Support\Facades\Hash::make($password),
                'email_verified_at' => now('UTC'), 'created_at' => now('UTC'), 'updated_at' => now('UTC'),
            ]);
        }
        return $this->activateFounder($invitationId, $token, $userId);
    }

    private function activateFounder(string $invitationId, string $token, string $userId): array
    {
        $db = \Illuminate\Support\Facades\DB::connection('pgsql_provider_control');
        return $db->transaction(function () use ($db, $invitationId, $token, $userId): array {
            // This is a founder-token transaction, with policies scoped to the invitation's exact tenant.
            $invite0 = $db->table('tenant_founder_invitations')->where('id', $invitationId)->first();
            if (! $invite0) { throw ProviderAccessException::approvalUnusable(); }
            foreach (['app.context_mode' => 'FOUNDER_ACTIVATION', 'app.user_id' => $userId,
                'app.founder_invitation_id' => $invitationId, 'app.provider_target_tenant_id' => $invite0->tenant_id,
                'app.provider_user_id' => '', 'app.provider_auth_version' => '', 'app.provider_step_up_at' => '',
                'app.provider_capability' => '', 'app.provider_operation_id' => '', 'app.provider_approval_id' => '',
                'app.provider_action' => '', 'app.tenant_id' => ''] as $key => $value) {
                $db->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
            }
            $tenant = $db->table('tenants')->where('id', $invite0->tenant_id)->lockForUpdate()->first();
            $invite = $db->table('tenant_founder_invitations')->where('id', $invitationId)->lockForUpdate()->first();
            $user = $db->selectOne('SELECT * FROM app_founder_activation_lock_user(?, ?)', [$invitationId, $userId]);
            if (! $tenant || ! $invite || ! $user || $tenant->status !== 'PROVISIONING'
                || $invite->accepted_at !== null || $invite->revoked_at !== null
                || now('UTC')->greaterThanOrEqualTo($invite->expires_at)
                || ! hash_equals($invite->token_hash, hash('sha256', $token))
                || $invite->email_canonical !== $user->email || $user->status !== 'ACTIVE'
                || $user->email_verified_at === null) { throw ProviderAccessException::approvalUnusable(); }
            $elsewhere = $db->table('tenant_memberships')->where('user_id', $userId)->where('status', 'ACTIVE')->where('tenant_id', '<>', $tenant->id)->exists();
            if ($elsewhere) { throw ProviderAccessException::approvalUnusable(); }
            $membership = $db->table('tenant_memberships')->where('tenant_id', $tenant->id)->where('user_id', $userId)->lockForUpdate()->first();
            if (! $membership) {
                $membershipId = (string) Str::uuid7();
                $db->table('tenant_memberships')->insert(['id' => $membershipId, 'tenant_id' => $tenant->id,
                    'user_id' => $userId, 'status' => 'ACTIVE', 'authorization_version' => 1,
                    'joined_at' => now('UTC'), 'created_at' => now('UTC'), 'updated_at' => now('UTC')]);
            } else {
                $membershipId = $membership->id;
                if ($membership->status !== 'ACTIVE') {
                    $db->table('tenant_memberships')->where('id', $membershipId)->update([
                        'status' => 'ACTIVE', 'authorization_version' => $membership->authorization_version + 1,
                        'updated_at' => now('UTC')]);
                }
            }
            $template = $db->table('role_templates')->where('code', 'company_admin')->where('version', 1)->where('status', 'ACTIVE')->first();
            if (! $template) { throw ProviderAccessException::approvalUnusable(); }
            $role = $db->table('roles')->where('tenant_id', $tenant->id)->where('normalized_name', 'company_admin')->lockForUpdate()->first();
            if (! $role) {
                $roleId = (string) Str::uuid7();
                $db->table('roles')->insert(['id' => $roleId, 'tenant_id' => $tenant->id,
                    'display_name' => 'Company Admin', 'normalized_name' => 'company_admin', 'status' => 'ACTIVE',
                    'source_template_id' => $template->id, 'version' => 1, 'archived_at' => null,
                    'created_at' => now('UTC'), 'updated_at' => now('UTC')]);
                foreach ($db->table('role_template_permissions')->where('template_id', $template->id)->get() as $grant) {
                    $db->table('role_permissions')->insert(['tenant_id' => $tenant->id, 'role_id' => $roleId,
                        'permission_key' => $grant->permission_key, 'scope' => $grant->scope]);
                }
            } else { $roleId = $role->id; }
            $db->table('membership_roles')->insertOrIgnore(['tenant_id' => $tenant->id,
                'membership_id' => $membershipId, 'role_id' => $roleId, 'assigned_by_user_id' => null, 'assigned_at' => now('UTC')]);
            $admin = $db->table('tenant_memberships as m')->join('users as u', 'u.id', '=', 'm.user_id')
                ->join('membership_roles as mr', 'mr.membership_id', '=', 'm.id')->join('roles as r', 'r.id', '=', 'mr.role_id')
                ->join('role_permissions as rp', 'rp.role_id', '=', 'r.id')->where('m.tenant_id', $tenant->id)
                ->where('m.status', 'ACTIVE')->where('u.status', 'ACTIVE')->whereNotNull('u.email_verified_at')
                ->where('r.status', 'ACTIVE')->where('rp.permission_key', 'company.administer')
                ->where('rp.scope', 'ALL_TENANT')->count() > 0;
            if (! $admin) { throw ProviderAccessException::approvalUnusable(); }
            $now = now('UTC');
            $db->table('tenant_founder_invitations')->where('id', $invitationId)->update(['existing_user_id' => $userId, 'accepted_at' => $now]);
            $db->table('tenants')->where('id', $tenant->id)->update(['status' => 'ACTIVE', 'updated_at' => $now]);
            $this->audit->appendFounderActivation($db, $userId, $tenant->id,
                AuditEventType::TENANT_FOUNDER_INVITATION_ACCEPTED, $invitationId, $membershipId);
            $this->audit->appendFounderActivation($db, $userId, $tenant->id,
                AuditEventType::TENANT_ACTIVATED, $tenant->id, $membershipId);
            return ['tenant_id' => $tenant->id, 'membership_id' => $membershipId, 'status' => 'ACTIVE'];
        });
    }

    private function assertProvider(ConnectionInterface $db, ProviderContext $actor, string $capability): void
    {
        $ok = $db->table('provider_users as p')->join('provider_user_capabilities as a', 'a.provider_user_id', '=', 'p.id')
            ->join('provider_capabilities as c', 'c.key', '=', 'a.capability_key')->where('p.id', $actor->providerUserId)
            ->where('p.status', 'ACTIVE')->whereNotNull('p.email_verified_at')->whereNotNull('p.mfa_enrolled_at')
            ->where('p.auth_version', $actor->authVersion)->where('a.capability_key', $capability)->where('c.status', 'ACTIVE')
            ->where(static fn ($q) => $q->whereNull('a.expires_at')->orWhere('a.expires_at', '>', now('UTC')))->select('p.id')->exists();
        if (! $ok || $actor->stepUpVerifiedAt === null || now('UTC')->timestamp - $actor->stepUpVerifiedAt >= 600) {
            throw ProviderAccessException::denied();
        }
    }

    private function assertApproval(ConnectionInterface $db, ?object $approval, object $operation, ProviderContext $actor): void
    {
        // A root-bypass decision (see applyRootBypassIfHeld()) is a self-decision by design, so
        // it must satisfy the independent-reviewer quorum below on its own; it is never combined
        // with a separate human reviewer's decision to reach a lower bar.
        $rootBypassed = $approval && $db->table('provider_approval_decisions')
            ->where('approval_request_id', $approval->id)->where('decision', 'APPROVE')
            ->where('approver_provider_user_id', $actor->providerUserId)->where('is_root_bypass', true)->exists();
        $provisionRevisionValid = $operation->action_key !== 'company.provision' || $rootBypassed
            || ($approval && (int) $approval->review_revision === (int) $operation->current_revision
                && $db->table('provider_approval_decisions')->where('approval_request_id', $approval->id)
                    ->where('decision', 'APPROVE')->where('decision_revision', $operation->current_revision)
                    ->where('approver_provider_user_id', '<>', $actor->providerUserId)
                    ->count() >= $approval->required_approvals);
        if (! $approval || $approval->status !== 'APPROVED' || $approval->operation_id !== $operation->id
            || ! $provisionRevisionValid
            || $approval->intent_digest !== $operation->intent_digest || $approval->action_key !== $operation->action_key
            || $approval->target_id !== $operation->target_tenant_id || $approval->requester_provider_user_id !== $actor->providerUserId
            || now('UTC')->greaterThanOrEqualTo($approval->expires_at) || $approval->consumed_at !== null
            || (! $rootBypassed && $db->table('provider_approval_decisions')->where('approval_request_id', $approval->id)
                ->where('decision', 'APPROVE')->where('approver_provider_user_id', '<>', $actor->providerUserId)->count() < $approval->required_approvals)
            || $db->table('provider_approval_decisions')->where('approval_request_id', $approval->id)->where('decision', 'REJECT')->exists()) {
            throw ProviderAccessException::approvalUnusable();
        }
    }

    /**
     * SUPER_ADMIN root bypass (owner decision D-4). If the requester holds the provider.root
     * capability, self-approve the request they just created in the same transaction: it skips
     * the independent-reviewer quorum entirely, but every use is its own, clearly-marked audit
     * row (never folded into the ordinary approval-requested event) and assertApproval() still
     * re-validates everything else (digest, target, expiry, no rejection) at execute time.
     * Returns the operation's resulting status: 'READY' if bypassed, 'PENDING_APPROVAL' if not.
     */
    private function applyRootBypassIfHeld(ConnectionInterface $db, ProviderContext $actor,
        string $operationId, string $approvalId, string $actionKey): string
    {
        $holdsRoot = $db->table('provider_users as p')
            ->join('provider_user_capabilities as a', 'a.provider_user_id', '=', 'p.id')
            ->join('provider_capabilities as c', 'c.key', '=', 'a.capability_key')
            ->where('p.id', $actor->providerUserId)->where('p.status', 'ACTIVE')
            ->whereNotNull('p.email_verified_at')->whereNotNull('p.mfa_enrolled_at')
            ->where('p.auth_version', $actor->authVersion)->where('a.capability_key', 'provider.root')
            ->where('c.status', 'ACTIVE')
            ->where(static fn ($q) => $q->whereNull('a.expires_at')->orWhere('a.expires_at', '>', now('UTC')))
            ->exists();
        if (! $holdsRoot) {
            return 'PENDING_APPROVAL';
        }
        $now = now('UTC');
        $db->table('provider_approval_decisions')->insert([
            'id' => (string) Str::uuid7(), 'approval_request_id' => $approvalId,
            'approver_provider_user_id' => $actor->providerUserId, 'decision' => 'APPROVE',
            'is_root_bypass' => true, 'decided_at' => $now,
        ]);
        $db->table('provider_approval_requests')->where('id', $approvalId)
            ->update(['status' => 'APPROVED', 'updated_at' => $now]);
        $db->table('provider_control_operations')->where('id', $operationId)
            ->update(['status' => 'READY', 'updated_at' => $now]);
        $this->audit->appendProviderControlMutation($db, $actor,
            AuditEventType::PROVIDER_CONTROL_OPERATION_ROOT_BYPASSED, $approvalId, null, ['action_key' => $actionKey]);
        return 'READY';
    }
}
