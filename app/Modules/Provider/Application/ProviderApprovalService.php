<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/** Internal control-plane primitive. No provisioning or recovery action is executed here. */
final class ProviderApprovalService
{
    public function __construct(
        private readonly ProviderAuthorizationService $authorization,
        private readonly ProviderDatabaseContext $dbContext,
        private readonly SecurityAuditWriter $audit,
    ) {}

    public function request(ProviderContext $requester, string $actionKey, string $targetId,
        string $reason, string $ticket): string
    {
        $policy = config('provider.approval_required', []);
        if (! array_key_exists($actionKey, $policy) || ! Str::isUuid($targetId)
            || ! in_array($actionKey, ['company.provision', 'company.recover'], true)) {
            throw ProviderAccessException::denied();
        }
        $reason = trim($reason);
        $ticket = trim($ticket);
        if (mb_strlen($reason) < 1 || mb_strlen($reason) > 500
            || strlen($ticket) < 1 || strlen($ticket) > 100
            || ! preg_match('/^[A-Za-z0-9][A-Za-z0-9._:\/-]*$/D', $ticket)) {
            throw ProviderAccessException::denied();
        }
        $quorum = (int) $policy[$actionKey];
        if ($quorum < 1 || $quorum > 3) {
            throw ProviderAccessException::denied();
        }
        $this->authorization->assertStepUp($requester);

        return $this->dbContext->run($requester->providerUserId, function (ConnectionInterface $connection)
            use ($requester, $actionKey, $targetId, $reason, $ticket, $quorum): string {
            $this->assertActiveVersion($connection, $requester);
            $this->authorization->assertCapability($requester, $actionKey);
            $id = (string) Str::uuid7();
            $connection->table('provider_approval_requests')->insert([
                'id' => $id, 'requester_provider_user_id' => $requester->providerUserId,
                'action_key' => $actionKey,
                'target_kind' => $actionKey === 'company.recover' ? 'TENANT' : 'PROVISIONING_INTENT',
                'target_id' => $targetId, 'reason' => $reason, 'ticket_reference' => $ticket,
                'required_approvals' => $quorum,
                'expires_at' => now('UTC')->addSeconds((int) config('provider.approval_lifetime_seconds')),
                'status' => 'PENDING', 'created_at' => now('UTC'), 'updated_at' => now('UTC'),
            ]);
            $this->audit->appendProviderMutation($requester->providerUserId, $requester->requestId,
                AuditEventType::PROVIDER_APPROVAL_REQUESTED, $id);
            return $id;
        });
    }

    public function decide(ProviderContext $reviewer, string $requestId, string $decision): string
    {
        if (! Str::isUuid($requestId) || ! in_array($decision, ['APPROVE', 'REJECT'], true)) {
            throw ProviderAccessException::approvalUnusable();
        }
        $this->authorization->assertStepUp($reviewer);

        return $this->dbContext->run($reviewer->providerUserId, function (ConnectionInterface $connection)
            use ($reviewer, $requestId, $decision): string {
            $this->assertActiveVersion($connection, $reviewer);
            $this->authorization->assertCapability($reviewer, 'provider.approval.review');
            $approval = $connection->table('provider_approval_requests')->where('id', $requestId)
                ->lockForUpdate()->first(['requester_provider_user_id', 'action_key', 'target_kind', 'status', 'expires_at', 'required_approvals']);
            $expectedTargetKind = $approval?->action_key === 'company.recover' ? 'TENANT' : 'PROVISIONING_INTENT';
            if (! $approval || ! in_array($approval->action_key, ['company.provision', 'company.recover'], true)
                || $approval->target_kind !== $expectedTargetKind || $approval->status !== 'PENDING'
                || now('UTC')->greaterThanOrEqualTo($approval->expires_at)
                || $approval->requester_provider_user_id === $reviewer->providerUserId) {
                throw ProviderAccessException::approvalUnusable();
            }
            if ($connection->table('provider_approval_decisions')->where('approval_request_id', $requestId)
                ->where('approver_provider_user_id', $reviewer->providerUserId)->exists()) {
                throw ProviderAccessException::approvalUnusable();
            }
            $connection->table('provider_approval_decisions')->insert([
                'id' => (string) Str::uuid7(), 'approval_request_id' => $requestId,
                'approver_provider_user_id' => $reviewer->providerUserId,
                'decision' => $decision, 'decided_at' => now('UTC'),
            ]);
            $count = $connection->table('provider_approval_decisions')->where('approval_request_id', $requestId)
                ->where('decision', 'APPROVE')->count();
            $status = $decision === 'REJECT' ? 'REJECTED'
                : ($count >= $approval->required_approvals ? 'APPROVED' : 'PENDING');
            $connection->table('provider_approval_requests')->where('id', $requestId)
                ->update(['status' => $status, 'updated_at' => now('UTC')]);
            $this->audit->appendProviderMutation($reviewer->providerUserId, $reviewer->requestId,
                $decision === 'APPROVE' ? AuditEventType::PROVIDER_APPROVAL_APPROVED
                    : AuditEventType::PROVIDER_APPROVAL_REJECTED, $requestId);
            return $status;
        });
    }

    public function revoke(ProviderContext $requester, string $requestId): void
    {
        if (! Str::isUuid($requestId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        $this->authorization->assertStepUp($requester);
        $this->dbContext->run($requester->providerUserId, function (ConnectionInterface $connection)
            use ($requester, $requestId): void {
            $this->assertActiveVersion($connection, $requester);
            $approval = $connection->table('provider_approval_requests')->where('id', $requestId)
                ->lockForUpdate()->first(['requester_provider_user_id', 'action_key', 'target_kind', 'status', 'expires_at']);
            $expectedTargetKind = $approval?->action_key === 'company.recover' ? 'TENANT' : 'PROVISIONING_INTENT';
            if (! $approval || ! in_array($approval->action_key, ['company.provision', 'company.recover'], true)
                || $approval->target_kind !== $expectedTargetKind
                || $approval->requester_provider_user_id !== $requester->providerUserId
                || ! in_array($approval->status, ['PENDING', 'APPROVED'], true)
                || now('UTC')->greaterThanOrEqualTo($approval->expires_at)) {
                throw ProviderAccessException::approvalUnusable();
            }
            $connection->table('provider_approval_requests')->where('id', $requestId)
                ->update(['status' => 'REVOKED', 'updated_at' => now('UTC')]);
            $this->audit->appendProviderMutation($requester->providerUserId, $requester->requestId,
                AuditEventType::PROVIDER_APPROVAL_REVOKED, $requestId);
        });
    }

    /** Caller must hold the provider transaction through the subsequent authorized action. */
    public function assertApprovalUsable(ConnectionInterface $connection, string $requestId,
        string $requesterId, string $actionKey, string $targetId): void
    {
        if (! in_array($actionKey, ['company.provision', 'company.recover'], true)
            || $connection->transactionLevel() < 1 || ! Str::isUuid($requestId)
            || ! Str::isUuid($requesterId) || ! Str::isUuid($targetId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        $approval = $connection->table('provider_approval_requests')->where('id', $requestId)
            ->lockForUpdate()->first([
                'status', 'expires_at', 'requester_provider_user_id', 'action_key', 'target_kind', 'target_id', 'required_approvals',
            ]);
        if (! $approval || $approval->status !== 'APPROVED'
            || now('UTC')->greaterThanOrEqualTo($approval->expires_at)
            || $approval->requester_provider_user_id !== $requesterId
            || ! in_array($approval->action_key, ['company.provision', 'company.recover'], true)
            || $approval->target_kind !== ($approval->action_key === 'company.recover' ? 'TENANT' : 'PROVISIONING_INTENT')
            || $approval->action_key !== $actionKey || $approval->target_id !== $targetId
            || $connection->table('provider_approval_decisions')->where('approval_request_id', $requestId)
                ->where('decision', 'APPROVE')->count() < $approval->required_approvals
            || $connection->table('provider_approval_decisions')->where('approval_request_id', $requestId)
                ->where('decision', 'REJECT')->exists()
            || ! $connection->table('provider_users')->where('id', $requesterId)
                ->where('status', 'ACTIVE')->whereNotNull('email_verified_at')->exists()
            || ! $connection->table('provider_user_capabilities as assignment')
                ->join('provider_capabilities as catalog', 'catalog.key', '=', 'assignment.capability_key')
                ->where('assignment.provider_user_id', $requesterId)
                ->where('assignment.capability_key', $actionKey)
                ->where('catalog.status', 'ACTIVE')
                ->where(static function ($query): void {
                    $query->whereNull('assignment.expires_at')
                        ->orWhere('assignment.expires_at', '>', now('UTC'));
                })->exists()) {
            throw ProviderAccessException::approvalUnusable();
        }
    }

    private function assertActiveVersion(ConnectionInterface $connection, ProviderContext $actor): void
    {
        $row = $connection->table('provider_users')->where('id', $actor->providerUserId)
            ->lockForUpdate()->first(['status', 'auth_version', 'email_verified_at']);
        if (! $row || $row->status !== 'ACTIVE' || $row->email_verified_at === null
            || $row->auth_version != $actor->authVersion) {
            throw ProviderAccessException::authRequired();
        }
    }
}
