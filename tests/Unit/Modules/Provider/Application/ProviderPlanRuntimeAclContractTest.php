<?php

namespace Tests\Unit\Modules\Provider\Application;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProviderPlanRuntimeAclContractTest extends TestCase
{
    #[DataProvider('grantFiles')]
    public function test_provider_runtime_receives_only_the_plan_and_subscription_acl_used_by_services(string $path): void
    {
        $sql = file_get_contents($path);

        self::assertIsString($sql);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE ON plans TO dl_provider;', $sql);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE ON plan_limits TO dl_provider;', $sql);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE ON tenant_subscriptions TO dl_provider;', $sql);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_limit_overrides TO dl_provider;', $sql);
        self::assertDoesNotMatchRegularExpression('/^\s*GRANT\s+ALL\b/im', $sql);
        self::assertStringNotContainsString('migrations_id_seq TO dl_provider', $sql);
    }

    public function test_forward_migration_applies_the_same_narrow_acl(): void
    {
        $apiRoot = dirname(__DIR__, 5);
        $migration = file_get_contents($apiRoot.'/database/migrations/2026_11_19_000073_grant_provider_plan_runtime_acl.php');

        self::assertIsString($migration);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE ON plans TO dl_provider', $migration);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE ON plan_limits TO dl_provider', $migration);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE ON tenant_subscriptions TO dl_provider', $migration);
        self::assertStringContainsString('GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_limit_overrides TO dl_provider', $migration);
        self::assertStringNotContainsString('BYPASSRLS', $migration);
        self::assertDoesNotMatchRegularExpression('/^\s*GRANT\s+ALL\b/im', $migration);
    }

    /** @return array<string, array{string}> */
    public static function grantFiles(): array
    {
        $workspace = dirname(dirname(__DIR__, 5));

        return [
            'acceptance roles-post' => [$workspace.'/tools/dev-db/acceptance/roles-post.sql'],
            'development roles-post' => [$workspace.'/tools/dev-db/bootstrap-roles-post.sql'],
        ];
    }
}
