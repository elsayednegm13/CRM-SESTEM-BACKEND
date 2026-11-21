<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\Exceptions\ActorSqlUnavailableException;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\ResourceScope;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

/**
 * First tenant-owned business table (docs/PLAN.md Phase 2). RLS (migration
 * 2026_10_23_000036) only proves tenant isolation; the ALL_TENANT/ASSIGNED/SELF scoping below
 * is application-layer, the same pattern as the legacy
 * App\Modules\Tenancy\Application\TenantAuthorizationService::allowsObject(). Every query uses
 * pgsql_tenant_runtime explicitly -- see TenantStaffRoleMutationService's docblock for why.
 */
final class LeadService
{
    private const CONNECTION = 'pgsql_tenant_runtime';
    private const STAGES = ['new', 'contacted', 'interested', 'followup', 'quotation', 'negotiation', 'won', 'lost'];

    public function __construct(private readonly TenantStaffAuthorizationService $authorization) {}

    /** @return array<int,array<string,mixed>> */
    public function listLeads(TenantStaffContext $actor, ?string $stage = null): array
    {
        $grants = $this->authorization->effectiveGrants($actor);
        $scopes = $grants['leads.view'] ?? null;
        if ($scopes === null) {
            throw new AuthorizationDeniedException;
        }
        $query = DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)
            ->where('status', 'ACTIVE');
        $this->applyScopeFilter($query, $scopes, $actor);
        if ($stage !== null) {
            if (! in_array($stage, self::STAGES, true)) {
                throw ValidationException::withMessages(['stage' => ['Invalid pipeline stage.']]);
            }
            $query->where('pipeline_stage', $stage);
        }

        return $query->orderByDesc('created_at')->get()->map(fn ($lead) => $this->present($lead))->all();
    }

    public function getLead(TenantStaffContext $actor, string $id): array
    {
        $grants = $this->authorization->effectiveGrants($actor);
        $scopes = $grants['leads.view'] ?? null;
        if ($scopes === null) {
            throw new AuthorizationDeniedException;
        }
        $lead = DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)
            ->where('id', $id)->first();
        if (! $lead || ! $this->rowInScope($lead, $scopes, $actor)) {
            throw new AuthorizationDeniedException;
        }

        return $this->present($lead);
    }

    /** @param array<string,mixed> $input */
    public function createLead(TenantStaffContext $actor, array $input): array
    {
        $grants = $this->authorization->effectiveGrants($actor);
        $scopes = $grants['leads.manage'] ?? null;
        if ($scopes === null) {
            throw new AuthorizationDeniedException;
        }
        $name = trim((string) ($input['name'] ?? ''));
        if ($name === '' || mb_strlen($name) > 160) {
            throw ValidationException::withMessages(['name' => ['A lead name is required.']]);
        }
        $assignedMembershipId = $input['assigned_membership_id'] ?? null;
        if (! in_array(ResourceScope::ALL_TENANT->value, $scopes, true)) {
            // Without tenant-wide manage, a lead can only be created for (and so visible to) self.
            $assignedMembershipId = $actor->membershipId;
        }
        $id = (string) Str::uuid7();
        $now = now('UTC');
        DB::connection(self::CONNECTION)->table('leads')->insert([
            'id' => $id, 'tenant_id' => $actor->tenantId, 'name' => $name,
            'phone' => $this->nullableString($input['phone'] ?? null, 32),
            'email' => $this->nullableString($input['email'] ?? null, 254),
            'city' => $this->nullableString($input['city'] ?? null, 100),
            'country' => $this->nullableString($input['country'] ?? null, 100),
            'source' => $this->nullableString($input['source'] ?? null, 100),
            'campaign' => $this->nullableString($input['campaign'] ?? null, 160),
            'pipeline_stage' => 'new', 'interest_level' => $this->validatedInterest($input['interest_level'] ?? null),
            'estimated_value_minor' => $this->validatedValue($input['estimated_value_minor'] ?? null),
            'status' => 'ACTIVE', 'assigned_membership_id' => $assignedMembershipId,
            'created_by_membership_id' => $actor->membershipId, 'last_contacted_at' => null,
            'created_at' => $now, 'updated_at' => $now,
        ]);

        return $this->getLead($actor, $id);
    }

    /** @param array<string,mixed> $input */
    public function updateLead(TenantStaffContext $actor, string $id, array $input): array
    {
        $lead = $this->leadForManage($actor, $id);
        $changes = [];
        foreach (['name' => 160, 'phone' => 32, 'email' => 254, 'city' => 100, 'country' => 100,
            'source' => 100, 'campaign' => 160] as $field => $max) {
            if (array_key_exists($field, $input)) {
                $value = $input[$field] === null ? null : trim((string) $input[$field]);
                if ($field === 'name' && ($value === '' || $value === null)) {
                    throw ValidationException::withMessages(['name' => ['A lead name is required.']]);
                }
                if (is_string($value) && mb_strlen($value) > $max) {
                    throw ValidationException::withMessages([$field => ["The {$field} is too long."]]);
                }
                $changes[$field] = $value;
            }
        }
        if (array_key_exists('interest_level', $input)) {
            $changes['interest_level'] = $this->validatedInterest($input['interest_level']);
        }
        if (array_key_exists('estimated_value_minor', $input)) {
            $changes['estimated_value_minor'] = $this->validatedValue($input['estimated_value_minor']);
        }
        if ($changes === []) {
            return $this->present($lead);
        }
        $changes['updated_at'] = now('UTC');
        DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)->where('id', $id)->update($changes);

        return $this->getLead($actor, $id);
    }

    public function updateStage(TenantStaffContext $actor, string $id, string $stage): array
    {
        if (! in_array($stage, self::STAGES, true)) {
            throw ValidationException::withMessages(['stage' => ['Invalid pipeline stage.']]);
        }
        $this->leadForManage($actor, $id);
        DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)->where('id', $id)
            ->update(['pipeline_stage' => $stage, 'last_contacted_at' => now('UTC'), 'updated_at' => now('UTC')]);

        return $this->getLead($actor, $id);
    }

    public function assignLead(TenantStaffContext $actor, string $id, string $membershipId): array
    {
        $grants = $this->authorization->effectiveGrants($actor);
        if (! in_array(ResourceScope::ALL_TENANT->value, $grants['leads.manage'] ?? [], true)) {
            // Reassigning to someone else is a tenant-wide action; ASSIGNED/SELF holders may not.
            throw new AuthorizationDeniedException;
        }
        $this->leadForManage($actor, $id);
        // Keep exists() on a granted column; see TenantStaffAccountService::createStaffMember.
        if (! DB::connection(self::CONNECTION)->table('tenant_staff_memberships')
            ->where('tenant_id', $actor->tenantId)->where('id', $membershipId)->where('status', 'ACTIVE')
            ->select('id')->exists()) {
            throw ValidationException::withMessages(['assigned_membership_id' => ['That staff member is not active in this company.']]);
        }
        if ((bool) config('f06_actor_sql.enabled')
            && in_array(app()->environment(), (array) config('f06_actor_sql.allow_env', []), true)) {
            try {
                DB::connection(self::CONNECTION)->selectOne('SELECT public.f06scope_assign_lead(?, ?) AS id', [$id, $membershipId]);
            } catch (QueryException $exception) {
                if (($exception->errorInfo[0] ?? $exception->getCode()) === '42883') {
                    throw ActorSqlUnavailableException::missingFunction();
                }
                throw $exception;
            }
        } else {
            DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)->where('id', $id)
                ->update(['assigned_membership_id' => $membershipId, 'updated_at' => now('UTC')]);
        }

        return $this->getLead($actor, $id);
    }

    public function archiveLead(TenantStaffContext $actor, string $id): void
    {
        $this->leadForManage($actor, $id);
        DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)->where('id', $id)
            ->update(['status' => 'ARCHIVED', 'updated_at' => now('UTC')]);
    }

    private function leadForManage(TenantStaffContext $actor, string $id): object
    {
        $grants = $this->authorization->effectiveGrants($actor);
        $scopes = $grants['leads.manage'] ?? null;
        if ($scopes === null) {
            throw new AuthorizationDeniedException;
        }
        $lead = DB::connection(self::CONNECTION)->table('leads')->where('tenant_id', $actor->tenantId)
            ->where('id', $id)->lockForUpdate()->first();
        if (! $lead || ! $this->rowInScope($lead, $scopes, $actor)) {
            throw new AuthorizationDeniedException;
        }

        return $lead;
    }

    /** @param array<int,string> $scopes */
    private function rowInScope(object $lead, array $scopes, TenantStaffContext $actor): bool
    {
        if (in_array(ResourceScope::ALL_TENANT->value, $scopes, true)) {
            return true;
        }
        if (in_array(ResourceScope::ASSIGNED->value, $scopes, true) && $lead->assigned_membership_id === $actor->membershipId) {
            return true;
        }
        if (in_array(ResourceScope::SELF->value, $scopes, true) && $lead->created_by_membership_id === $actor->membershipId) {
            return true;
        }

        return false;
    }

    /** @param array<int,string> $scopes */
    private function applyScopeFilter($query, array $scopes, TenantStaffContext $actor): void
    {
        if (in_array(ResourceScope::ALL_TENANT->value, $scopes, true)) {
            return;
        }
        $query->where(function ($q) use ($scopes, $actor): void {
            if (in_array(ResourceScope::ASSIGNED->value, $scopes, true)) {
                $q->orWhere('assigned_membership_id', $actor->membershipId);
            }
            if (in_array(ResourceScope::SELF->value, $scopes, true)) {
                $q->orWhere('created_by_membership_id', $actor->membershipId);
            }
        });
    }

    private function present(object $lead): array
    {
        return [
            'id' => $lead->id, 'name' => $lead->name, 'phone' => $lead->phone, 'email' => $lead->email,
            'city' => $lead->city, 'country' => $lead->country, 'source' => $lead->source, 'campaign' => $lead->campaign,
            'pipeline_stage' => $lead->pipeline_stage, 'interest_level' => $lead->interest_level,
            'estimated_value_minor' => $lead->estimated_value_minor === null ? null : (int) $lead->estimated_value_minor,
            'status' => $lead->status, 'assigned_membership_id' => $lead->assigned_membership_id,
            'created_by_membership_id' => $lead->created_by_membership_id,
            'last_contacted_at' => $lead->last_contacted_at, 'created_at' => $lead->created_at,
        ];
    }

    private function nullableString(mixed $value, int $max): ?string
    {
        if ($value === null) {
            return null;
        }
        $value = trim((string) $value);
        if ($value === '') {
            return null;
        }
        if (mb_strlen($value) > $max) {
            throw ValidationException::withMessages(['value' => ['A field exceeds its maximum length.']]);
        }

        return $value;
    }

    private function validatedInterest(mixed $value): ?string
    {
        if ($value === null) {
            return null;
        }
        if (! in_array($value, ['HOT', 'WARM', 'COLD'], true)) {
            throw ValidationException::withMessages(['interest_level' => ['Invalid interest level.']]);
        }

        return $value;
    }

    private function validatedValue(mixed $value): ?int
    {
        if ($value === null) {
            return null;
        }
        if (! is_int($value) || $value < 0) {
            throw ValidationException::withMessages(['estimated_value_minor' => ['Invalid estimated value.']]);
        }

        return $value;
    }
}
