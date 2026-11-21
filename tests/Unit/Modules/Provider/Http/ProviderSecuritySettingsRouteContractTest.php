<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Provider\Http;

use App\Modules\Provider\Http\Middleware\ValidateProviderSecuritySettingsSession;
use App\Modules\Provider\Http\Middleware\ValidateProviderSession;
use App\Modules\Provider\Http\Middleware\RequireProviderOrigin;
use Tests\TestCase;

final class ProviderSecuritySettingsRouteContractTest extends TestCase
{
    public function test_m01_m03_settings_use_restricted_self_service_while_provisioning_keeps_full_guard(): void
    {
        foreach (['api.v1.super.auth.mfa.settings.status', 'api.v1.super.auth.mfa.settings.enroll.start',
            'api.v1.super.auth.mfa.settings.enroll.confirm'] as $name) {
            $route = app('router')->getRoutes()->getByName($name);
            self::assertNotNull($route);
            self::assertContains(ValidateProviderSecuritySettingsSession::class, $route->gatherMiddleware());
            self::assertNotContains(ValidateProviderSession::class, $route->gatherMiddleware());
        }

        $provision = app('router')->getRoutes()->getByName('api.v1.super.companies.store');
        self::assertNotNull($provision);
        self::assertContains(ValidateProviderSession::class, $provision->gatherMiddleware());
        self::assertNotContains(ValidateProviderSecuritySettingsSession::class, $provision->gatherMiddleware());
    }

    public function test_m02_m06_confirmation_rotates_authority_and_requires_session_bound_one_time_state(): void
    {
        $source = file_get_contents(app_path('Modules/Provider/Application/ProviderAuthenticationService.php'));
        self::assertIsString($source);
        foreach ([
            "'session_id' => \$request->session()->getId()",
            "(\$pending['session_id'] ?? null) !== \$request->session()->getId()",
            "now('UTC')->timestamp >= (int) \$pending['expires_at']",
            "'auth_version' => \$context->authVersion + 1",
            "\$request->session()->forget('provider.settings_mfa')",
            '$this->logout($request)',
        ] as $needle) {
            self::assertStringContainsString($needle, $source);
        }
    }

    public function test_m03_m08_high_risk_provisioning_still_requires_step_up_and_authority_receipt(): void
    {
        $source = file_get_contents(app_path('Modules/Provider/Application/ProviderDirectProvisionService.php'));
        self::assertIsString($source);
        self::assertStringContainsString('$this->authorization->assertStepUp($actor)', $source);
        self::assertStringContainsString('$this->authority->obtainProvisionReceipt(', $source);
    }

    public function test_m04_m07_optional_login_and_settings_routes_preserve_origin_method_and_full_guard_boundaries(): void
    {
        $routes = app('router')->getRoutes();
        $login = $routes->getByName('api.v1.super.auth.login');
        self::assertNotNull($login);
        self::assertSame(['POST'], $login->methods());
        self::assertContains(RequireProviderOrigin::class, $login->gatherMiddleware());
        self::assertNotContains(ValidateProviderSession::class, $login->gatherMiddleware());

        $expected = [
            'api.v1.super.auth.mfa.settings.status' => ['GET', 'HEAD'],
            'api.v1.super.auth.mfa.settings.enroll.start' => ['POST'],
            'api.v1.super.auth.mfa.settings.enroll.confirm' => ['POST'],
        ];
        foreach ($expected as $name => $methods) {
            $route = $routes->getByName($name);
            self::assertNotNull($route);
            self::assertSame($methods, $route->methods());
            self::assertContains(RequireProviderOrigin::class, $route->gatherMiddleware());
            self::assertContains(ValidateProviderSecuritySettingsSession::class, $route->gatherMiddleware());
        }
    }
}
