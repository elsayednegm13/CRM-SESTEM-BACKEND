<?php

namespace Tests\Feature\Identity;

use App\Modules\Identity\Application\TenantStaffRateLimiter;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use App\Modules\Identity\Domain\Exceptions\AuthSessionExpiredException;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Identity\Http\Middleware\ValidateTenantStaffSession;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUser;
use App\Modules\Identity\Infrastructure\Persistence\TenantStaffUserProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Mockery;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

final class IdentityAuthenticationTest extends TestCase
{
    public function test_email_normalization_is_canonical_for_unicode_and_idn_domains(): void
    {
        $normalizer = app(EmailAddressNormalizer::class);
        self::assertSame('owner@example.test', $normalizer->normalize("  OWNER@EXAMPLE.TEST\t"));
        self::assertSame('user@xn--bcher-kva.example', $normalizer->normalize(' USER@bücher.example '));
        self::assertSame('user@xn--bcher-kva.example', $normalizer->normalize("user@bu\u{0308}cher.example"));
    }

    public function test_unconfigured_tenant_auth_fails_before_a_global_identity_lookup(): void
    {
        config(['identity.tenant_auth_client_enabled' => false]);

        $this->withHeaders(['Accept' => 'application/json', 'Origin' => 'http://localhost:3001'])
            ->postJson('/api/v1/auth/login', [
                'email' => 'legacy@example.test',
                'password' => 'irrelevant secret',
            ])
            ->assertStatus(503)
            ->assertJsonPath('error', 'runtime_unavailable');
    }

    public function test_tenant_auth_remains_closed_outside_local_and_testing_even_if_enabled(): void
    {
        config(['identity.tenant_auth_client_enabled' => true, 'app.env' => 'production']);

        $this->withHeaders(['Accept' => 'application/json', 'Origin' => 'http://localhost:3001'])
            ->postJson('/api/v1/auth/login', [
                'email' => 'staff@example.test',
                'password' => 'synthetic only',
            ])
            ->assertStatus(503)
            ->assertJsonPath('error', 'runtime_unavailable');
    }

    public function test_auth_routes_no_longer_dispatch_to_global_user_or_password_broker_controllers(): void
    {
        $routes = file_get_contents(base_path('routes/api.php'));
        self::assertIsString($routes);
        self::assertStringContainsString('[TenantStaffAuthController::class, \'login\']', $routes);
        self::assertStringContainsString('Route::post(\'/forgot-password\', AuthRecoveryNotImplementedController::class)', $routes);
        self::assertStringNotContainsString('[AuthController::class, \'login\']', $routes);
        self::assertStringNotContainsString('[PasswordController::class, \'forgot\']', $routes);
        self::assertStringNotContainsString('[PasswordController::class, \'reset\']', $routes);
    }

    public function test_tenant_session_provider_never_authenticates_by_email_or_password(): void
    {
        $provider = new TenantStaffUserProvider(app('hash'), TenantStaffUser::class);

        self::assertNull($provider->retrieveByCredentials(['email' => 'same@example.test', 'password' => 'not a credential query']));
        self::assertFalse($provider->validateCredentials(new TenantStaffUser(), ['password' => 'not a credential query']));
    }

    public function test_login_limiter_separates_tenant_identity_but_keeps_ip_ceiling(): void
    {
        $limiter = app(TenantStaffRateLimiter::class);
        $request = request();
        $request->server->set('REMOTE_ADDR', '192.0.2.'.random_int(1, 254));
        $tenantA = new TenantHostContext((string) Str::uuid(), 'a', 'a.id02.localhost', 'id02.localhost', 'LOCAL_TEST');
        $tenantB = new TenantHostContext((string) Str::uuid(), 'b', 'b.id02.localhost', 'id02.localhost', 'LOCAL_TEST');
        config(['identity.login.max_failures' => 5, 'identity.login.ip_max_failures' => 100, 'identity.login.decay_seconds' => 900]);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $limiter->recordFailure($tenantA, 'same@example.test', $request);
        }

        $limiter->assertLoginAllowed($tenantB, 'same@example.test', $request);
        $this->expectException(\App\Modules\Identity\Domain\Exceptions\AuthRateLimitedException::class);
        $limiter->assertLoginAllowed($tenantA, 'same@example.test', $request);
    }

    public function test_tenant_session_cookie_is_host_only_http_only_and_same_site_lax(): void
    {
        self::assertNull(config('session.domain'));
        self::assertTrue(config('session.http_only'));
        self::assertSame('lax', config('session.same_site'));
        self::assertTrue(config('session.secure'));
    }

    public function test_tenant_absolute_session_expires_at_the_eight_hour_boundary_and_rejects_invalid_timestamps(): void
    {
        $lifetime = 28_800;
        $authenticatedAt = 1_800_000_000;
        config(['identity.absolute_session_lifetime' => $lifetime]);

        $user = new TenantStaffUser();
        $user->setRawAttributes(['id' => (string) Str::uuid()]);
        $guard = Mockery::mock(StatefulGuard::class);
        $guard->shouldReceive('user')->times(6)->andReturn($user);
        $guard->shouldReceive('logout')->times(5);
        Auth::shouldReceive('guard')->with('tenant_staff')->andReturn($guard);

        $requestForStart = static function (mixed $sessionStart) use ($user): Request {
            $session = new Store('closeout-test', new ArraySessionHandler(120));
            $session->start();
            if ($sessionStart !== null) {
                $session->put('identity.tenant_staff.authenticated_at', $sessionStart);
            }

            $request = Request::create('/api/v1/auth/me');
            $request->setLaravelSession($session);
            $request->attributes->set('tenant_staff_context', new TenantStaffContext(
                (string) Str::uuid(),
                'company.id02.localhost',
                (string) $user->getAuthIdentifier(),
                (string) Str::uuid(),
                1,
                1,
            ));

            return $request;
        };

        $middleware = new ValidateTenantStaffSession();

        try {
            Carbon::setTestNow(Carbon::createFromTimestampUTC($authenticatedAt + $lifetime - 1));
            $validRequest = $requestForStart($authenticatedAt);
            $validResponse = $middleware->handle(
                $validRequest,
                static fn (Request $request): Response => new Response('ok', 200),
            );

            self::assertSame(200, $validResponse->getStatusCode());
            self::assertTrue($validRequest->session()->exists('identity.tenant_staff.authenticated_at'));

            foreach ([
                [$authenticatedAt + $lifetime, $authenticatedAt],
                [$authenticatedAt + $lifetime + 1, $authenticatedAt],
                [$authenticatedAt + $lifetime - 1, $authenticatedAt + $lifetime],
                [$authenticatedAt + $lifetime - 1, null],
                [$authenticatedAt + $lifetime - 1, 'invalid'],
            ] as [$now, $sessionStart]) {
                Carbon::setTestNow(Carbon::createFromTimestampUTC($now));
                $expiredRequest = $requestForStart($sessionStart);

                try {
                    $middleware->handle(
                        $expiredRequest,
                        static fn (Request $request): Response => new Response('unexpected', 200),
                    );
                    self::fail('The tenant session must expire at its absolute limit or for an invalid start time.');
                } catch (AuthSessionExpiredException) {
                    self::assertFalse($expiredRequest->session()->exists('identity.tenant_staff'));
                }
            }
        } finally {
            Carbon::setTestNow();
        }
    }

    public function test_v1_founder_invitation_routes_remain_absent_and_direct_provisioning_requires_provider_auth(): void
    {
        foreach ([(string) Str::uuid(), '00000000-0000-4000-8000-000000000001'] as $invitation) {
            foreach (['POST', 'GET', 'PUT', 'PATCH', 'DELETE'] as $method) {
                $this->json($method, '/api/v1/onboarding/founder-invitations/'.$invitation.'/accept',
                    ['token' => str_repeat('a', 48)])
                    ->assertStatus(503)
                    ->assertJsonPath('error', 'runtime_unavailable');
            }
        }

        // The Laravel test client always resolves HTTP_HOST from config('app.url')
        // (here localhost:8000), not from withServerVariables(); the allowed-host
        // list must match what the client actually sends.
        config([
            'provider.api_hosts' => ['localhost:8000'],
            'provider.allowed_origins' => ['http://localhost:3002'],
            'cors.allowed_origins' => ['http://localhost:3002'],
            'sanctum.stateful' => array_values(array_unique([
                ...config('sanctum.stateful', []), 'localhost:3002',
            ])),
        ]);
        $this->withServerVariables(['HTTP_HOST' => 'localhost:8000'])
            ->withHeader('Origin', 'http://localhost:3002')
            ->postJson('/api/v1/super/provisioning-operations', [])
            ->assertStatus(503)
            ->assertJsonPath('error', 'runtime_unavailable');
        $this->withServerVariables(['HTTP_HOST' => 'localhost:8000'])
            ->withHeader('Origin', 'http://localhost:3002')
            ->postJson('/api/v1/super/provisioning-operations/00000000-0000-4000-8000-000000000001/execute', [])
            ->assertStatus(503)
            ->assertJsonPath('error', 'runtime_unavailable');
    }
}
