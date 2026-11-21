<?php

namespace Tests\Unit\Modules\Tenancy\Application;

use App\Modules\Tenancy\Application\AuthorizationSecurityEvents;
use App\Modules\Tenancy\Application\TenantAuthorizationService;
use App\Modules\Tenancy\Domain\TenantContext;
use App\Modules\Tenancy\Infrastructure\Persistence\RlsDatabaseContext;
use App\Modules\Tenancy\Infrastructure\Persistence\TenantContextGuard;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class TenantAuthorizationSyntheticScopeTest extends TestCase
{
    public function test_synthetic_scope_facts_are_evaluated_without_database_permission_rows(): void
    {
        $ids = $this->ids();
        $service = $this->service([
            'tenants' => [(object) ['status' => 'ACTIVE']],
            'users' => [(object) ['status' => 'ACTIVE', 'auth_version' => 0]],
            'tenant_memberships' => [(object) ['status' => 'ACTIVE', 'authorization_version' => 1]],
            'membership_roles as mr' => [
                (object) ['id' => 'role-assigned', 'display_name' => 'Assigned', 'version' => 1],
                (object) ['id' => 'role-self', 'display_name' => 'Self', 'version' => 1],
            ],
            'role_permissions as rp' => [
                (object) ['permission_key' => 'synthetic.scope.view', 'scope' => 'ASSIGNED', 'scopeable' => true,
                    'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]'],
                (object) ['permission_key' => 'synthetic.scope.view', 'scope' => 'SELF', 'scopeable' => true,
                    'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]'],
            ],
            'permissions' => [(object) ['scopeable' => true,
                'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]', 'delegable' => true]],
        ]);
        $context = new TenantContext($ids['user'], $ids['tenant'], $ids['membership'], 1, 0, $ids['request']);

        self::assertSame(['ASSIGNED', 'SELF'], $service->snapshot($context)['grants']['synthetic.scope.view']);
        self::assertTrue($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], ['assigned_user_id' => $ids['user']]));
        self::assertTrue($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], ['owner_user_id' => $ids['user']]));
        self::assertFalse($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], []));
        self::assertFalse($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], ['assigned_user_id' => $this->uuid()]));
        self::assertFalse($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], ['owner_user_id' => $this->uuid()]));
        self::assertFalse($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], ['team_id' => 'synthetic-team']));
        self::assertFalse($service->allowsObject($context, 'synthetic.scope.view', $this->uuid(), ['assigned_user_id' => $ids['user']]));
    }

    public function test_all_tenant_dominates_narrower_scope_and_none_is_omitted(): void
    {
        $ids = $this->ids();
        $service = $this->service([
            'tenants' => [(object) ['status' => 'ACTIVE']],
            'users' => [(object) ['status' => 'ACTIVE', 'auth_version' => 0]],
            'tenant_memberships' => [(object) ['status' => 'ACTIVE', 'authorization_version' => 1]],
            'membership_roles as mr' => [(object) ['id' => 'role-all', 'display_name' => 'All tenant', 'version' => 1]],
            'role_permissions as rp' => [
                (object) ['permission_key' => 'synthetic.scope.view', 'scope' => 'ASSIGNED', 'scopeable' => true,
                    'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]'],
                (object) ['permission_key' => 'synthetic.scope.view', 'scope' => 'ALL_TENANT', 'scopeable' => true,
                    'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]'],
                (object) ['permission_key' => 'synthetic.scope.none', 'scope' => 'NONE', 'scopeable' => true,
                    'allowed_scopes' => '["NONE"]'],
            ],
            'permissions' => [(object) ['scopeable' => true,
                'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]', 'delegable' => true]],
        ]);
        $context = new TenantContext($ids['user'], $ids['tenant'], $ids['membership'], 1, 0, $ids['request']);

        self::assertSame(['ALL_TENANT'], $service->snapshot($context)['grants']['synthetic.scope.view']);
        self::assertArrayNotHasKey('synthetic.scope.none', $service->snapshot($context)['grants']);
        self::assertTrue($service->allowsObject($context, 'synthetic.scope.view', $ids['tenant'], []));
    }

    public function test_synthetic_delegation_requires_the_exact_scope_or_all_tenant(): void
    {
        $service = $this->service([
            'permissions' => [(object) ['scopeable' => true,
                'allowed_scopes' => '["ALL_TENANT","TEAM","ASSIGNED","SELF"]', 'delegable' => true]],
        ]);

        $assigned = ['grants' => ['synthetic.scope.view' => ['ASSIGNED']]];
        foreach (['ALL_TENANT', 'TEAM', 'SELF', 'NONE', 'UNREGISTERED', null] as $scope) {
            self::assertFalse($service->canDelegateWithinGuard($assigned, 'synthetic.scope.view', $scope));
        }
        self::assertTrue($service->canDelegateWithinGuard($assigned, 'synthetic.scope.view', 'ASSIGNED'));
        self::assertFalse($service->canDelegateWithinGuard(
            ['grants' => ['synthetic.scope.view' => ['TEAM']]], 'synthetic.scope.view', 'ASSIGNED',
        ));
        self::assertTrue($service->canDelegateWithinGuard(
            ['grants' => ['synthetic.scope.view' => ['ALL_TENANT']]], 'synthetic.scope.view', 'SELF',
        ));
        self::assertFalse($service->canDelegateWithinGuard(
            ['grants' => ['synthetic.scope.view' => ['ALL_TENANT']]], 'company.administer', 'ALL_TENANT',
        ));
    }

    private function service(array $rows): TenantAuthorizationService
    {
        DB::shouldReceive('transactionLevel')->zeroOrMoreTimes()->andReturn(0);
        DB::shouldReceive('transaction')->zeroOrMoreTimes()->andReturnUsing(static fn (callable $operation) => $operation());
        DB::shouldReceive('selectOne')->zeroOrMoreTimes()->andReturn((object) ['value' => null]);
        DB::shouldReceive('table')->zeroOrMoreTimes()->andReturnUsing(static function (string $table) use ($rows): SyntheticScopeQuery {
            return new SyntheticScopeQuery($rows[$table] ?? []);
        });

        return new TenantAuthorizationService(new TenantContextGuard(new RlsDatabaseContext()), new AuthorizationSecurityEvents());
    }

    private function ids(): array
    {
        return ['user' => $this->uuid(), 'tenant' => $this->uuid(), 'membership' => $this->uuid(), 'request' => $this->uuid()];
    }

    private function uuid(): string
    {
        return sprintf('%s-%s-4%s-%s-%s', bin2hex(random_bytes(4)), bin2hex(random_bytes(2)),
            substr(bin2hex(random_bytes(2)), 1), bin2hex(random_bytes(2)), bin2hex(random_bytes(6)));
    }
}

/** Local row source for the unit test; it never opens a database connection. */
final class SyntheticScopeQuery
{
    public function __construct(private readonly array $rows)
    {
    }

    public function where(mixed ...$arguments): self
    {
        return $this;
    }

    public function whereIn(mixed ...$arguments): self
    {
        return $this;
    }

    public function join(mixed ...$arguments): self
    {
        return $this;
    }

    public function orderBy(mixed ...$arguments): self
    {
        return $this;
    }

    public function sharedLock(): self
    {
        return $this;
    }

    public function first(mixed ...$arguments): ?object
    {
        return $this->rows[0] ?? null;
    }

    public function get(mixed ...$arguments): Collection
    {
        return Collection::make($this->rows);
    }
}
