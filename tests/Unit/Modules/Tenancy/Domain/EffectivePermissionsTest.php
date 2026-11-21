<?php

namespace Tests\Unit\Modules\Tenancy\Domain;

use App\Modules\Identity\Domain\EffectivePermissions;
use PHPUnit\Framework\TestCase;

final class EffectivePermissionsTest extends TestCase
{
    public function test_it_unions_multiple_role_grants_with_independent_direct_grants(): void
    {
        $resolver = new EffectivePermissions();
        $catalog = $this->syntheticCatalog();
        $roleA = [
            ['permission_key' => 'test.leads.read', 'scope' => 'ASSIGNED'],
        ];
        $roleB = [
            ['permission_key' => 'test.tasks.update', 'scope' => 'SELF'],
        ];

        $effective = $resolver->resolve(
            [...$roleA, ...$roleB],
            [
                ['permission_key' => 'test.leads.read', 'scope' => 'SELF'],
                ['permission_key' => 'test.reports.view', 'scope' => null],
            ],
            $catalog,
        );

        self::assertSame([
            'test.leads.read' => ['ASSIGNED', 'SELF'],
            'test.reports.view' => [null],
            'test.tasks.update' => ['SELF'],
        ], $effective);
    }

    public function test_all_tenant_scope_dominates_narrower_scopes_and_none_grants_no_right(): void
    {
        $effective = (new EffectivePermissions())->resolve(
            [
                ['permission_key' => 'test.leads.read', 'scope' => 'ASSIGNED'],
                ['permission_key' => 'test.leads.read', 'scope' => 'ALL_TENANT'],
                ['permission_key' => 'test.tasks.update', 'scope' => 'NONE'],
            ],
            [],
            $this->syntheticCatalog(),
        );

        self::assertSame(['test.leads.read' => ['ALL_TENANT']], $effective);
    }

    public function test_direct_grant_changes_are_per_person_and_do_not_imply_rights_from_role_names(): void
    {
        $resolver = new EffectivePermissions();
        $catalog = $this->syntheticCatalog();
        $roleGrants = [['permission_key' => 'test.leads.read', 'scope' => 'ASSIGNED']];
        $employeeA = $resolver->resolve($roleGrants, [['permission_key' => 'test.tasks.update', 'scope' => 'SELF']], $catalog);
        $employeeB = $resolver->resolve($roleGrants, [], $catalog);
        $afterRevocationA = $resolver->resolve($roleGrants, [], $catalog);

        self::assertSame(['test.leads.read' => ['ASSIGNED'], 'test.tasks.update' => ['SELF']], $employeeA);
        self::assertSame(['test.leads.read' => ['ASSIGNED']], $employeeB);
        self::assertSame($employeeB, $afterRevocationA);
        self::assertSame($roleGrants, [['permission_key' => 'test.leads.read', 'scope' => 'ASSIGNED']]);
    }

    public function test_unknown_inactive_malformed_and_unauthorized_catalog_permissions_fail_closed(): void
    {
        $resolver = new EffectivePermissions();
        $catalog = $this->syntheticCatalog();

        self::assertNull($resolver->resolve([['permission_key' => 'test.not_registered', 'scope' => null]], [], $catalog));
        self::assertNull($resolver->resolve([['permission_key' => 'test.retired.read', 'scope' => 'SELF']], [], $catalog));
        self::assertNull($resolver->resolve([['permission_key' => 'test.leads.read', 'scope' => 'TEAM']], [], $catalog));
        self::assertNull($resolver->resolve([], [['permission_key' => 'test.company.admin', 'scope' => 'ALL_TENANT']], $catalog));
        self::assertNull($resolver->resolve([false], [], $catalog));
    }

    private function syntheticCatalog(): array
    {
        return [
            'test.leads.read' => ['status' => 'ACTIVE', 'scopeable' => true, 'allowed_scopes' => ['ALL_TENANT', 'ASSIGNED', 'SELF'], 'delegable' => true],
            'test.tasks.update' => ['status' => 'ACTIVE', 'scopeable' => true, 'allowed_scopes' => ['SELF', 'NONE'], 'delegable' => true],
            'test.reports.view' => ['status' => 'ACTIVE', 'scopeable' => false, 'allowed_scopes' => [], 'delegable' => true],
            'test.company.admin' => ['status' => 'ACTIVE', 'scopeable' => true, 'allowed_scopes' => ['ALL_TENANT'], 'delegable' => false],
            'test.retired.read' => ['status' => 'RETIRED', 'scopeable' => true, 'allowed_scopes' => ['SELF'], 'delegable' => true],
        ];
    }
}
