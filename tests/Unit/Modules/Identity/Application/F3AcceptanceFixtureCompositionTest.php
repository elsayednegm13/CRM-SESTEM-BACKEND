<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\F3AcceptanceFixtureOrchestrator;
use App\Modules\Identity\Application\LaravelF3AcceptanceFixtureOrchestrator;
use App\Modules\Provider\Application\ProviderAuthenticationService;
use App\Modules\Provider\Application\ProviderBootstrapService;
use App\Modules\Provider\Application\ProviderDirectProvisionService;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class F3AcceptanceFixtureCompositionTest extends TestCase
{
    public function test_f02_f06_real_composition_depends_on_official_services_and_has_no_sql_api(): void
    {
        $reflection = new ReflectionClass(LaravelF3AcceptanceFixtureOrchestrator::class);
        $types = [];
        foreach ($reflection->getConstructor()?->getParameters() ?? [] as $parameter) {
            $types[] = (string) $parameter->getType();
        }
        self::assertContains(ProviderBootstrapService::class, $types);
        self::assertContains(ProviderAuthenticationService::class, $types);
        self::assertContains(ProviderDirectProvisionService::class, $types);
        self::assertTrue($reflection->implementsInterface(F3AcceptanceFixtureOrchestrator::class));
        self::assertCount(2, $reflection->getMethods(\ReflectionMethod::IS_PUBLIC));
    }

    public function test_f02_exercises_unenrolled_ordinary_provider_branch_before_sensitive_enrollment(): void
    {
        $source = file_get_contents((new ReflectionClass(LaravelF3AcceptanceFixtureOrchestrator::class))->getFileName());
        self::assertIsString($source);
        $ordinary = strpos($source, '$ordinaryContext = $this->providerAuthorization->current($request)');
        $enroll = strpos($source, '$this->providerAuth->startSettingsEnrollment(');
        self::assertNotFalse($ordinary);
        self::assertNotFalse($enroll);
        self::assertLessThan($enroll, $ordinary);
        self::assertStringContainsString('$this->providerAuthorization->capabilities($ordinaryContext);', $source);
        self::assertStringContainsString('$this->providerAuth->stepUp(', $source);
        self::assertStringContainsString("config('tenancy.base_domain')", $source);
        self::assertStringNotContainsString("'daleel.localhost'", $source);
        self::assertStringContainsString('$this->environmentScope($baseDomain)', $source);
        self::assertStringContainsString("return 'LOCAL_TEST';", $source);
        self::assertStringContainsString('RestrictedTenantProbeCleanupException', $source);
        self::assertStringContainsString('$cleanupFailure = $exception;', $source);
        self::assertStringContainsString("\$request->attributes->remove('tenant_staff_authority_cleanup');", $source);
    }
}
