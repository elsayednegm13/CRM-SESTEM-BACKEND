<?php

namespace App\Modules\Provider\Application;

use App\Modules\Provider\Domain\ProviderAccessException;
use App\Modules\Provider\Domain\ProviderContext;
use App\Modules\Provider\Infrastructure\Persistence\ProviderDatabaseContext;
use App\Modules\Shared\Audit\AuditEventType;
use App\Modules\Shared\Audit\SecurityAuditWriter;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

/**
 * Global plan catalog (plans + plan_limits). Global reference data, no RLS -- same rule as
 * permissions/role_templates (docs/RLS_ARCHITECTURE.md). provider.plans.manage is the PHP-level
 * enforcement, same pattern as ProviderTeamService. Mutations run inside ProviderDatabaseContext
 * so the data change and its audit row share one transaction, even though the tables they touch
 * carry no RLS themselves.
 */
final class PlanCatalogService
{
    public function __construct(
        private readonly ProviderAuthorizationService $authorization,
        private readonly ProviderDatabaseContext $context,
        private readonly SecurityAuditWriter $audit,
    ) {}

    public function listPlans(ProviderContext $actor): array
    {
        $this->authorization->assertCapability($actor, 'plans.manage');
        $plans = DB::connection('pgsql_provider')->table('plans')->orderBy('sort_order')
            ->get(['id', 'code', 'display_name', 'price_monthly_minor', 'price_annual_minor',
                'currency', 'status', 'sort_order']);
        $limits = DB::connection('pgsql_provider')->table('plan_limits')
            ->whereIn('plan_id', $plans->pluck('id'))->get()->groupBy('plan_id');

        return $plans->map(fn ($plan) => [
            'id' => $plan->id, 'code' => $plan->code, 'display_name' => $plan->display_name,
            'price_monthly_minor' => (int) $plan->price_monthly_minor,
            'price_annual_minor' => (int) $plan->price_annual_minor,
            'currency' => $plan->currency, 'status' => $plan->status,
            'limits' => ($limits->get($plan->id) ?? collect())
                ->mapWithKeys(fn ($row) => [$row->limit_key => $row->limit_value === null ? null : (int) $row->limit_value])->all(),
        ])->values()->all();
    }

    /** @return array{id:string} */
    public function createPlan(ProviderContext $actor, array $input): array
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'plans.manage');
        $code = mb_strtolower(trim((string) ($input['code'] ?? '')));
        $display = trim((string) ($input['display_name'] ?? ''));
        $monthly = $input['price_monthly_minor'] ?? null;
        $annual = $input['price_annual_minor'] ?? null;
        $limits = $input['limits'] ?? [];
        if (! preg_match('/^[a-z][a-z0-9_]{0,38}[a-z0-9]$/D', $code) || $display === '' || mb_strlen($display) > 120
            || ! is_int($monthly) || $monthly <= 0 || ! is_int($annual) || $annual <= 0 || ! is_array($limits)) {
            throw ValidationException::withMessages(['plan' => ['The plan definition is invalid.']]);
        }
        foreach ($limits as $key => $value) {
            if (! preg_match('/^[a-z][a-z0-9_]{0,62}[a-z0-9]$/D', (string) $key)
                || ($value !== null && (! is_int($value) || $value < 0))) {
                throw ValidationException::withMessages(['limits' => ["Invalid limit: {$key}"]]);
            }
        }
        if (DB::connection('pgsql_provider')->table('plans')->where('code', $code)->exists()) {
            throw ValidationException::withMessages(['code' => ['A plan with this code already exists.']]);
        }
        $id = (string) Str::uuid7();
        $now = now('UTC');
        $maxOrder = (int) DB::connection('pgsql_provider')->table('plans')->max('sort_order');
        return $this->context->run($actor->providerUserId, function ($db) use ($actor, $id, $code, $display, $monthly, $annual, $limits, $maxOrder, $now): array {
            $db->table('plans')->insert([
                'id' => $id, 'code' => $code, 'display_name' => $display,
                'price_monthly_minor' => $monthly, 'price_annual_minor' => $annual,
                'currency' => 'EGP', 'status' => 'ACTIVE', 'sort_order' => $maxOrder + 1,
                'created_at' => $now, 'updated_at' => $now,
            ]);
            foreach ($limits as $key => $value) {
                $db->table('plan_limits')->insert([
                    'plan_id' => $id, 'limit_key' => $key, 'limit_value' => $value,
                    'created_at' => $now, 'updated_at' => $now,
                ]);
            }
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_PLAN_CREATED, $id);
            return ['id' => $id];
        });
    }

    public function updatePlan(ProviderContext $actor, string $planId, array $input): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'plans.manage');
        if (! Str::isUuid($planId)) {
            throw ProviderAccessException::approvalUnusable();
        }
        $plan = DB::connection('pgsql_provider')->table('plans')->where('id', $planId)->first(['id']);
        if (! $plan) {
            throw ProviderAccessException::approvalUnusable();
        }
        $changes = [];
        if (array_key_exists('display_name', $input)) {
            $display = trim((string) $input['display_name']);
            if ($display === '' || mb_strlen($display) > 120) {
                throw ValidationException::withMessages(['display_name' => ['Invalid display name.']]);
            }
            $changes['display_name'] = $display;
        }
        if (array_key_exists('price_monthly_minor', $input)) {
            if (! is_int($input['price_monthly_minor']) || $input['price_monthly_minor'] <= 0) {
                throw ValidationException::withMessages(['price_monthly_minor' => ['Invalid price.']]);
            }
            $changes['price_monthly_minor'] = $input['price_monthly_minor'];
        }
        if (array_key_exists('price_annual_minor', $input)) {
            if (! is_int($input['price_annual_minor']) || $input['price_annual_minor'] <= 0) {
                throw ValidationException::withMessages(['price_annual_minor' => ['Invalid price.']]);
            }
            $changes['price_annual_minor'] = $input['price_annual_minor'];
        }
        if (array_key_exists('status', $input)) {
            if (! in_array($input['status'], ['ACTIVE', 'RETIRED'], true)) {
                throw ValidationException::withMessages(['status' => ['Invalid status.']]);
            }
            $changes['status'] = $input['status'];
        }
        if ($changes === []) {
            return;
        }
        $changedFields = array_keys($changes);
        $changes['updated_at'] = now('UTC');
        $this->context->run($actor->providerUserId, function ($db) use ($actor, $planId, $changes, $changedFields): void {
            $db->table('plans')->where('id', $planId)->update($changes);
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_PLAN_UPDATED, $planId, ['changed_fields' => $changedFields]);
        });
    }

    public function setLimit(ProviderContext $actor, string $planId, string $key, ?int $value): void
    {
        $this->authorization->assertStepUp($actor);
        $this->authorization->assertCapability($actor, 'plans.manage');
        if (! Str::isUuid($planId) || ! preg_match('/^[a-z][a-z0-9_]{0,62}[a-z0-9]$/D', $key)
            || ($value !== null && $value < 0)) {
            throw ValidationException::withMessages(['limit' => ['Invalid limit key or value.']]);
        }
        if (! DB::connection('pgsql_provider')->table('plans')->where('id', $planId)->exists()) {
            throw ProviderAccessException::approvalUnusable();
        }
        $now = now('UTC');
        $this->context->run($actor->providerUserId, function ($db) use ($actor, $planId, $key, $value, $now): void {
            $db->table('plan_limits')->upsert(
                ['plan_id' => $planId, 'limit_key' => $key, 'limit_value' => $value, 'created_at' => $now, 'updated_at' => $now],
                ['plan_id', 'limit_key'], ['limit_value', 'updated_at'],
            );
            $this->audit->appendProviderMutation($actor->providerUserId, $actor->requestId,
                AuditEventType::PROVIDER_PLAN_LIMIT_SET, $planId, ['limit_key' => $key]);
        });
    }
}
