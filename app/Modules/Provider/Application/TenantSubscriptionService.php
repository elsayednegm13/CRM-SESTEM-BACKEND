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
use Illuminate\Validation\ValidationException;

/**
 * Per-company subscription and limit overrides. tenant_subscriptions/tenant_limit_overrides
 * carry tenant_id and are RLS-protected (migration 2026_10_23_000033); writes run inside
 * ProviderDatabaseContext with a target tenant id, matching app_provider_admin_tenant_allowed().
 * This is a direct admin action (D-6: no dual-control requirement), unlike company.provision/
 * recover/lifecycle, so it does not use the provider_control_operations/approval pipeline.
 */
final class TenantSubscriptionService
{
    public function __construct(
        private readonly ProviderAuthorizationService $authorization,
        private readonly ProviderDatabaseContext $context,
        private readonly SecurityAuditWriter $audit,
    ) {}

    public function getSubscription(ProviderContext $actor, string $tenantId): ?array
    {
        $this->authorization->assertCapability($actor, 'company.subscription.manage');
        if (! Str::isUuid($tenantId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        return $this->context->run($actor->providerUserId, function (ConnectionInterface $db) use ($tenantId): ?array {
            $subscription = $db->table('tenant_subscriptions as s')->join('plans as p', 'p.id', '=', 's.plan_id')
                ->where('s.tenant_id', $tenantId)->where('s.status', 'ACTIVE')
                ->first(['s.id', 's.plan_id', 'p.code as plan_code', 'p.display_name as plan_name',
                    's.billing_cycle', 's.started_at', 's.current_period_ends_at']);
            if (! $subscription) {
                return null;
            }
            $overrides = $db->table('tenant_limit_overrides')->where('tenant_id', $tenantId)
                ->get(['limit_key', 'limit_value', 'reason'])
                ->mapWithKeys(fn ($row) => [$row->limit_key => ['value' => $row->limit_value, 'reason' => $row->reason]]);
            $planLimits = DB::connection('pgsql_provider')->table('plan_limits')
                ->where('plan_id', $subscription->plan_id)->get(['limit_key', 'limit_value']);
            $effective = $planLimits->mapWithKeys(fn ($row) => [$row->limit_key => [
                'value' => $overrides->has($row->limit_key) ? $overrides[$row->limit_key]['value'] : $row->limit_value,
                'overridden' => $overrides->has($row->limit_key),
            ]]);

            return [
                'id' => $subscription->id, 'plan_id' => $subscription->plan_id,
                'plan_code' => $subscription->plan_code, 'plan_name' => $subscription->plan_name,
                'billing_cycle' => $subscription->billing_cycle, 'started_at' => $subscription->started_at,
                'current_period_ends_at' => $subscription->current_period_ends_at,
                'limits' => $effective->all(), 'overrides' => $overrides->all(),
            ];
        }, $tenantId);
    }

    /** @return array{id:string} */
    public function assignPlan(ProviderContext $actor, string $tenantId, string $planId, string $billingCycle): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.subscription.manage');
        if (! Str::isUuid($tenantId) || ! Str::isUuid($planId) || ! in_array($billingCycle, ['MONTHLY', 'ANNUAL'], true)) {
            throw ValidationException::withMessages(['subscription' => ['The subscription request is invalid.']]);
        }
        if (! DB::connection('pgsql_provider')->table('plans')->where('id', $planId)->where('status', 'ACTIVE')->exists()) {
            throw ValidationException::withMessages(['plan_id' => ['That plan is not available.']]);
        }
        try {
            return $this->context->run($actor->providerUserId, function (ConnectionInterface $db) use ($actor, $tenantId, $planId, $billingCycle): array {
                $now = now('UTC');
                $db->table('tenant_subscriptions')->where('tenant_id', $tenantId)->where('status', 'ACTIVE')
                    ->update(['status' => 'CANCELLED', 'cancelled_at' => $now, 'updated_at' => $now]);
                $id = (string) Str::uuid7();
                // tenants carries no SELECT policy for this lightweight 'PROVIDER' mode (it is
                // reserved for TENANT/PROVIDER_CONTROL contexts), so existence is proved by the
                // tenant_id foreign key below, not a pre-check -- same pattern as createRecovery().
                $db->table('tenant_subscriptions')->insert([
                    'id' => $id, 'tenant_id' => $tenantId, 'plan_id' => $planId,
                    'billing_cycle' => $billingCycle, 'status' => 'ACTIVE', 'started_at' => $now,
                    'current_period_ends_at' => null, 'cancelled_at' => null,
                    'created_by_provider_user_id' => $actor->providerUserId,
                    'created_at' => $now, 'updated_at' => $now,
                ]);
                $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                    AuditEventType::TENANT_SUBSCRIPTION_ASSIGNED, $tenantId, ['plan_id' => $planId], $tenantId);
                return ['id' => $id];
            }, $tenantId);
        } catch (\Illuminate\Database\QueryException $exception) {
            $sqlState = is_object($exception->getPrevious()) && isset($exception->getPrevious()->errorInfo[0])
                ? (string) $exception->getPrevious()->errorInfo[0] : (string) $exception->getCode();
            if ($sqlState === '23503') {
                throw ValidationException::withMessages(['tenant_id' => ['That company does not exist.']]);
            }
            throw $exception;
        }
    }

    public function cancelSubscription(ProviderContext $actor, string $tenantId): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.subscription.manage');
        if (! Str::isUuid($tenantId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        $this->context->run($actor->providerUserId, function (ConnectionInterface $db) use ($actor, $tenantId): void {
            $now = now('UTC');
            $updated = $db->table('tenant_subscriptions')->where('tenant_id', $tenantId)->where('status', 'ACTIVE')
                ->update(['status' => 'CANCELLED', 'cancelled_at' => $now, 'updated_at' => $now]);
            if ($updated === 0) {
                throw ProviderAccessException::approvalUnusable();
            }
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::TENANT_SUBSCRIPTION_CANCELLED, $tenantId, [], $tenantId);
        }, $tenantId);
    }

    public function setLimitOverride(ProviderContext $actor, string $tenantId, string $key, ?int $value, string $reason): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.subscription.manage');
        $reason = trim($reason);
        if (! Str::isUuid($tenantId) || ! preg_match('/^[a-z][a-z0-9_]{0,62}[a-z0-9]$/D', $key)
            || ($value !== null && $value < 0) || $reason === '' || mb_strlen($reason) > 500) {
            throw ValidationException::withMessages(['override' => ['Invalid override key, value, or reason.']]);
        }
        try {
            $this->context->run($actor->providerUserId, function (ConnectionInterface $db) use ($actor, $tenantId, $key, $value, $reason): void {
                $now = now('UTC');
                $db->table('tenant_limit_overrides')->upsert(
                    ['id' => (string) Str::uuid7(), 'tenant_id' => $tenantId, 'limit_key' => $key, 'limit_value' => $value,
                        'reason' => $reason, 'created_by_provider_user_id' => $actor->providerUserId,
                        'created_at' => $now, 'updated_at' => $now],
                    ['tenant_id', 'limit_key'], ['limit_value', 'reason', 'created_by_provider_user_id', 'updated_at'],
                );
                $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                    AuditEventType::TENANT_LIMIT_OVERRIDE_SET, $tenantId, ['limit_key' => $key], $tenantId);
            }, $tenantId);
        } catch (\Illuminate\Database\QueryException $exception) {
            $sqlState = is_object($exception->getPrevious()) && isset($exception->getPrevious()->errorInfo[0])
                ? (string) $exception->getPrevious()->errorInfo[0] : (string) $exception->getCode();
            if ($sqlState === '23503') {
                throw ValidationException::withMessages(['tenant_id' => ['That company does not exist.']]);
            }
            throw $exception;
        }
    }

    public function removeLimitOverride(ProviderContext $actor, string $tenantId, string $key): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'company.subscription.manage');
        if (! Str::isUuid($tenantId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        $this->context->run($actor->providerUserId, function (ConnectionInterface $db) use ($actor, $tenantId, $key): void {
            $deleted = $db->table('tenant_limit_overrides')->where('tenant_id', $tenantId)->where('limit_key', $key)->delete();
            if ($deleted === 0) {
                throw ProviderAccessException::approvalUnusable();
            }
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::TENANT_LIMIT_OVERRIDE_REMOVED, $tenantId, ['limit_key' => $key], $tenantId);
        }, $tenantId);
    }
}
