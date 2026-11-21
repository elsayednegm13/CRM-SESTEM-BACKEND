<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\F3AcceptanceFixturePrewriteAttestor;
use App\Modules\Identity\Application\LaravelF3AcceptanceFixturePrewriteAttestor;
use App\Modules\Identity\Application\TenantRuntimeConnectionProvider;
use App\Modules\Identity\Application\TenantRuntimeIdentityAttestor;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class F3AcceptanceFixturePrewriteContractTest extends TestCase
{
    public function test_f3_01_command_requires_attestation_before_orchestration(): void
    {
        $source = file_get_contents(dirname(__DIR__, 5).'/app/Console/Commands/PrepareF3AcceptanceFixture.php');
        self::assertIsString($source);
        self::assertStringContainsString("\$attestor->attest(\$validated['run_id'], \$validated['permit_id'])", $source);
        self::assertLessThan(
            strpos($source, '$workflow->prepare($validated)'),
            strpos($source, '$attestor->attest('),
        );
    }

    public function test_f3_01_attestor_uses_restricted_runtime_identity_and_private_permit(): void
    {
        $reflection = new ReflectionClass(LaravelF3AcceptanceFixturePrewriteAttestor::class);
        $types = array_map(static fn ($parameter): string => (string) $parameter->getType(), $reflection->getConstructor()?->getParameters() ?? []);
        self::assertTrue($reflection->implementsInterface(F3AcceptanceFixturePrewriteAttestor::class));
        self::assertContains(TenantRuntimeConnectionProvider::class, $types);
        self::assertContains(TenantRuntimeIdentityAttestor::class, $types);
        $source = file_get_contents($reflection->getFileName());
        self::assertIsString($source);
        foreach (['/run/f3/fixture-permit.json', 'beginTransaction()', 'identity->attest($connection)', 'rollBack()'] as $needle) {
            self::assertStringContainsString($needle, $source);
        }
    }
}
