<?php

namespace Tests\Feature\Tenancy;

use App\Modules\Identity\Application\TenantStaffAuthorizationService;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\AuthorizationDeniedException;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

final class TenantStaffAuthorizationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        if (config('database.connections.pgsql_tenant_runtime.database') !== 'daleel_fnd_id02_auth_test') {
            self::markTestSkipped('The test-only FND-ID-02 PostgreSQL target is not configured.');
        }
    }

    public function test_existing_role_view_catalog_key_allows_active_role_assignment(): void
    {
        $context = $this->fixtureContext('FND_ID02_FIXTURE_USER_A_ID', 'FND_ID02_FIXTURE_MEMBERSHIP_A_ID', 'FND_ID02_FIXTURE_TENANT_A_ID', 'FND_ID02_FIXTURE_HOST_A');
        $roles = $this->withContext($context, fn () => app(TenantStaffAuthorizationService::class)->listRoles($context));

        self::assertContains('FND-ID-02 Synthetic Admin', array_column($roles, 'name'));
    }

    public function test_existing_direct_role_view_grant_allows_and_missing_grant_denies(): void
    {
        $direct = $this->fixtureContext('FND_ID02_FIXTURE_DIRECT_USER_ID', 'FND_ID02_FIXTURE_DIRECT_MEMBERSHIP_ID', 'FND_ID02_FIXTURE_TENANT_A_ID', 'FND_ID02_FIXTURE_HOST_A');
        $roles = $this->withContext($direct, fn () => app(TenantStaffAuthorizationService::class)->listRoles($direct));
        self::assertNotEmpty($roles);

        $denied = $this->fixtureContext('FND_ID02_FIXTURE_DENIED_USER_ID', 'FND_ID02_FIXTURE_DENIED_MEMBERSHIP_ID', 'FND_ID02_FIXTURE_TENANT_A_ID', 'FND_ID02_FIXTURE_HOST_A');
        $this->expectException(AuthorizationDeniedException::class);
        $this->withContext($denied, fn () => app(TenantStaffAuthorizationService::class)->listRoles($denied));
    }

    private function fixtureContext(string $userKey, string $membershipKey, string $tenantKey, string $hostKey): TenantStaffContext
    {
        foreach ([$userKey, $membershipKey, $tenantKey, $hostKey] as $key) {
            if (! is_string(env($key)) || env($key) === '') {
                self::markTestSkipped('Synthetic FND-ID-02 authorization fixture values are absent.');
            }
        }

        return new TenantStaffContext(
            (string) env($tenantKey),
            (string) env($hostKey),
            (string) env($userKey),
            (string) env($membershipKey),
            1,
            1,
        );
    }

    private function withContext(TenantStaffContext $context, callable $operation): mixed
    {
        $connection = DB::connection('pgsql_tenant_runtime');

        return $connection->transaction(function () use ($connection, $context, $operation): mixed {
            $connection->selectOne("SELECT pg_catalog.set_config('app.context_mode', 'TENANT', true)");
            $connection->selectOne("SELECT pg_catalog.set_config('app.tenant_id', ?, true)", [$context->tenantId]);
            $connection->selectOne("SELECT pg_catalog.set_config('app.user_id', ?, true)", [$context->userId]);

            return $operation();
        });
    }
}
