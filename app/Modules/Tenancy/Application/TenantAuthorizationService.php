<?php

namespace App\Modules\Tenancy\Application;

use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use App\Modules\Tenancy\Domain\ResourceScope;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantContextGuard;
use Closure;
use Illuminate\Support\Facades\DB;

/** Central, uncached PostgreSQL authorization for the current tenant membership. */
final class TenantAuthorizationService
{
    public function __construct(
        private readonly TenantContextGuard $guard,
        private readonly AuthorizationSecurityEvents $events,
    ) {
    }

    public function snapshot(TenantContext $context): array
    {
        return $this->guard->run($context, fn () => $this->snapshotWithinGuard($context));
    }

    public function listRoles(TenantContext $context): array
    {
        return $this->runWithCapability($context, 'role.view', function () use ($context): array {
            return DB::table('roles')->where('tenant_id', $context->tenantId)->where('status', 'ACTIVE')
                ->orderBy('normalized_name')->get(['id', 'display_name', 'version'])
                ->map(fn ($role) => ['id' => $role->id, 'name' => $role->display_name, 'version' => (int) $role->version])
                ->all();
        });
    }

    public function runWithCapability(TenantContext $context, string $permission, Closure $operation, bool $write = false): mixed
    {
        try {
            return $this->guard->run($context, function () use ($context, $permission, $operation): mixed {
                $snapshot = $this->snapshotWithinGuard($context);
                $metadata = $this->catalog($permission);
                if (! $metadata || $metadata->scopeable || ! in_array(null, $snapshot['grants'][$permission] ?? [], true)) {
                    throw new AuthorizationDeniedException;
                }
                return $operation($snapshot);
            }, $write);
        } catch (AuthorizationDeniedException $exception) {
            $this->events->emit('AuthorizationDenied', 'denied', $context);
            throw $exception;
        }
    }

    /** Resource facts must come from a server-loaded, same-tenant object. */
    public function allowsObject(TenantContext $context, string $permission, string $objectTenantId, array $facts): bool
    {
        return $this->guard->run($context, function () use ($context, $permission, $objectTenantId, $facts): bool {
            $metadata = $this->catalog($permission);
            if (! $metadata || ! $metadata->scopeable || $objectTenantId !== $context->tenantId) {
                return false;
            }
            $scopes = $this->snapshotWithinGuard($context)['grants'][$permission] ?? [];
            if (in_array(ResourceScope::ALL_TENANT->value, $scopes, true)) {
                return true;
            }
            if (in_array(ResourceScope::ASSIGNED->value, $scopes, true)
                && ($facts['assigned_user_id'] ?? null) === $context->userId) {
                return true;
            }
            if (in_array(ResourceScope::SELF->value, $scopes, true)
                && ($facts['owner_user_id'] ?? null) === $context->userId) {
                return true;
            }
            // TEAM and NONE never authorize a resource in 07B.
            return false;
        });
    }

    /** @internal Call only inside a TenantContextGuard transaction. */
    public function snapshotWithinGuard(TenantContext $context): array
    {
        $roles = DB::table('membership_roles as mr')
            ->join('roles as r', function ($join): void {
                $join->on('r.tenant_id', '=', 'mr.tenant_id')->on('r.id', '=', 'mr.role_id');
            })
            ->where('mr.tenant_id', $context->tenantId)
            ->where('mr.membership_id', $context->membershipId)
            ->where('r.status', 'ACTIVE')
            ->orderBy('r.id')->get(['r.id', 'r.display_name', 'r.version']);

        $roleIds = $roles->pluck('id')->all();
        $grants = [];
        if ($roleIds !== []) {
            $rows = DB::table('role_permissions as rp')
                ->join('permissions as p', 'p.key', '=', 'rp.permission_key')
                ->where('rp.tenant_id', $context->tenantId)
                ->whereIn('rp.role_id', $roleIds)
                ->where('p.status', 'ACTIVE')
                ->orderBy('rp.permission_key')->get(['rp.permission_key', 'rp.scope', 'p.scopeable', 'p.allowed_scopes']);
            foreach ($rows as $row) {
                $allowed = json_decode($row->allowed_scopes, true, 512, JSON_THROW_ON_ERROR);
                if (($row->scopeable && (! $row->scope || ! in_array($row->scope, $allowed, true)))
                    || (! $row->scopeable && $row->scope !== null)) {
                    throw new AuthorizationDeniedException;
                }
                if ($row->scope === ResourceScope::NONE->value) {
                    continue;
                }
                $grants[$row->permission_key] ??= [];
                if (! in_array($row->scope, $grants[$row->permission_key], true)) {
                    $grants[$row->permission_key][] = $row->scope;
                }
            }
        }
        ksort($grants);
        foreach ($grants as &$scopes) {
            if (in_array(ResourceScope::ALL_TENANT->value, $scopes, true)) {
                $scopes = [ResourceScope::ALL_TENANT->value];
            } else {
                sort($scopes);
            }
        }
        unset($scopes);

        return [
            'membership_id' => $context->membershipId,
            'authorization_version' => $context->membershipAuthorizationVersion,
            'roles' => $roles->map(fn ($role) => ['id' => $role->id, 'name' => $role->display_name, 'version' => (int) $role->version])->all(),
            'grants' => $grants,
        ];
    }

    /** @internal The caller must already hold the tenant-first write guard. */
    public function canDelegateWithinGuard(array $actorSnapshot, string $permission, ?string $proposedScope): bool
    {
        if ($permission === 'company.administer') {
            return false;
        }
        $metadata = $this->catalog($permission);
        if (! $metadata || ! $metadata->delegable) {
            return false;
        }
        $owned = $actorSnapshot['grants'][$permission] ?? [];
        if (! $metadata->scopeable) {
            return $proposedScope === null && in_array(null, $owned, true);
        }
        $allowed = json_decode($metadata->allowed_scopes, true, 512, JSON_THROW_ON_ERROR);
        if ($proposedScope === null || $proposedScope === ResourceScope::NONE->value
            || $proposedScope === ResourceScope::TEAM->value
            || ! in_array($proposedScope, $allowed, true)) {
            return false;
        }
        return in_array(ResourceScope::ALL_TENANT->value, $owned, true)
            || in_array($proposedScope, $owned, true);
    }

    private function catalog(string $permission): ?object
    {
        return DB::table('permissions')->where('key', $permission)->where('status', 'ACTIVE')
            ->first(['scopeable', 'allowed_scopes', 'delegable']);
    }
}
