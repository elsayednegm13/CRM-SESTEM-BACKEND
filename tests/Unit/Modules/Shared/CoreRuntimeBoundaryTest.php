<?php

namespace Tests\Unit\Modules\Shared;

use App\Modules\Shared\Http\Middleware\CoreRuntimeBoundary;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

final class CoreRuntimeBoundaryTest extends TestCase
{
    public function test_missing_runtime_identity_fails_closed(): void
    {
        config()->set('core_runtime.mode', null);

        self::assertSame(503, $this->invokeMiddleware('/api/v1/health/live')->getStatusCode());
    }

    public function test_legacy_cannot_serve_protected_routes_or_hold_trusted_credentials(): void
    {
        $this->roles('legacy');
        self::assertSame(204, $this->invokeMiddleware('/api/v1/health/live')->getStatusCode());
        self::assertSame(404, $this->invokeMiddleware('/api/v1/super/auth/me')->getStatusCode());

        config()->set('database.connections.pgsql_provider_control.username', 'dl_provider_ctl');
        self::assertSame(503, $this->invokeMiddleware('/api/v1/health/live')->getStatusCode());

        config()->set('database.connections.pgsql_provider_control.username', null);
        self::assertSame(503, $this->invokeMiddleware('/api/v1/health/live', 'platform.core01.localhost')->getStatusCode());

        config()->set('database.connections.pgsql_provider.password', 'synthetic-extra-secret');
        self::assertSame(503, $this->invokeMiddleware('/api/v1/health/live')->getStatusCode());
    }

    public function test_trusted_requires_distinct_non_owner_runtime_credentials(): void
    {
        $this->roles('trusted');
        self::assertSame(204, $this->invokeMiddleware('/api/v1/super/auth/me')->getStatusCode());

        config()->set('database.connections.pgsql_tenant_runtime.username', 'dl_truntime');
        self::assertSame(503, $this->invokeMiddleware('/api/v1/super/auth/me')->getStatusCode());

        config()->set('database.connections.pgsql_tenant_runtime.username', 'dl_core_truntime');
        config()->set('database.connections.pgsql.username', 'daleel_b10b_owner');
        self::assertSame(503, $this->invokeMiddleware('/api/v1/super/auth/me')->getStatusCode());

        config()->set('database.connections.pgsql.username', null);
        self::assertSame(503, $this->invokeMiddleware('/api/v1/super/auth/me', 'legacy.core01.localhost')->getStatusCode());
    }

    public function test_trusted_contract_failures_keep_generic_response(): void
    {
        $this->roles('trusted');
        foreach ([
            'TRUSTED_DEFAULT_CONNECTION' => fn () => config()->set('database.default', 'pgsql'),
            'TRUSTED_TENANT_IDENTITY' => fn () => config()->set('database.connections.pgsql_tenant_runtime.username', 'dl_other'),
            'TRUSTED_PROVIDER_IDENTITY' => fn () => config()->set('database.connections.pgsql_provider.username', null),
            'TRUSTED_LEGACY_CREDENTIAL_PRESENT' => fn () => config()->set('database.connections.pgsql.username', 'dl_truntime'),
        ] as $reason => $mutate) {
            $this->roles('trusted');
            $mutate();
            $response = $this->invokeMiddleware('/api/v1/super/auth/me');
            self::assertSame(503, $response->getStatusCode(), $reason);
            self::assertSame(['error' => 'runtime_unavailable'], json_decode((string) $response->getContent(), true));
        }
    }

    public function test_early_boundary_rejection_is_correlated_before_routes_run(): void
    {
        config()->set('core_runtime.mode', null);

        $response = $this->getJson('http://platform.core01.localhost/api/v1/health/live');

        $response->assertStatus(503)->assertExactJson(['error' => 'runtime_unavailable']);
        self::assertTrue(Str::isUuid((string) $response->headers->get('X-Request-ID')));
        self::assertStringNotContainsString('IDENTITY_CONFIGURATION', (string) $response->getContent());
    }

    private function roles(string $mode): void
    {
        config()->set('core_runtime.mode', $mode);
        config()->set('core_runtime.owner_login', 'daleel_b10b_owner');
        config()->set('core_runtime.base_host', 'core01.localhost');
        config()->set('core_runtime.legacy_host', 'legacy.core01.localhost');
        config()->set('session.domain', null);
        config()->set('core_sql.trusted_tenant_login', 'dl_core_truntime');
        config()->set('core_sql.legacy_tenant_login', 'dl_truntime');
        config()->set('app.key', 'base64:synthetic-test-only-key');
        config()->set('database.default', $mode === 'trusted' ? 'pgsql_provider' : 'pgsql_tenant_runtime');
        foreach (config('database.connections') as $name => $connection) {
            if (($connection['driver'] ?? null) === 'pgsql') {
                config()->set("database.connections.$name.password", null);
                config()->set("database.connections.$name.url", null);
                // The runtime boundary must reject an unexpected PostgreSQL
                // identity. Start this isolated unit fixture with no identity,
                // then add only the connection that each mode permits.
                config()->set("database.connections.$name.username", null);
            }
        }
        config()->set('database.connections.pgsql.username', null);
        config()->set('database.connections.pgsql_provider.username', $mode === 'trusted' ? 'dl_provider' : null);
        config()->set('database.connections.pgsql_provider_control.username', null);
        config()->set('database.connections.pgsql_onboarding.username', null);
        config()->set('database.connections.pgsql_hostname_resolver.username', null);
        config()->set('database.connections.pgsql_tenant_auth.username', null);
        config()->set('database.connections.pgsql_f06_bootstrap.username', null);
        config()->set('database.connections.pgsql_tenant_runtime.username', $mode === 'trusted' ? 'dl_core_truntime' : 'dl_truntime');
    }

    private function invokeMiddleware(string $path, ?string $host = null): Response
    {
        return (new CoreRuntimeBoundary)->handle(
            Request::create($path, 'GET', [], [], [], ['HTTP_HOST' => $host ?? (config('core_runtime.mode') === 'legacy' ? 'legacy.core01.localhost' : 'platform.core01.localhost')]),
            static fn () => new Response('', 204),
        );
    }
}
