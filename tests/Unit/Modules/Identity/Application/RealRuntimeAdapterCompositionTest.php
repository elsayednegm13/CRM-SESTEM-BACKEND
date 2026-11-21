<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\LaravelRestrictedTenantRuntimeAdapter;
use App\Modules\Identity\Application\TenantAuthorityBridge;
use App\Modules\Identity\Application\TenantStaffLoginService;
use ReflectionProperty;
use Tests\TestCase;

final class RealRuntimeAdapterCompositionTest extends TestCase
{
    public function test_container_composes_adapter_with_real_login_service(): void
    {
        $adapter = app(LaravelRestrictedTenantRuntimeAdapter::class);
        $bridgeProperty = new ReflectionProperty($adapter, 'bridge');
        $bridge = $bridgeProperty->getValue($adapter);
        self::assertInstanceOf(TenantAuthorityBridge::class, $bridge);
        $loginProperty = new ReflectionProperty($bridge, 'login');
        self::assertInstanceOf(TenantStaffLoginService::class, $loginProperty->getValue($bridge));
    }

    public function test_runtime_command_is_disabled_by_default(): void
    {
        config()->set('f3_acceptance.enabled', false);
        $this->artisan('dcrm:f3-restricted-runtime-probe')
            ->expectsOutput('F3_RUNTIME_PROBE_DISABLED')
            ->assertExitCode(1);
    }
}
