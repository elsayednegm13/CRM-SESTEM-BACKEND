<?php

namespace Tests\Unit\Modules\Identity\Http;

use App\Modules\Identity\Http\Middleware\EnsureTenantLoginClientProof;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Tests\TestCase;

final class EnsureTenantLoginClientProofTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('core_sql.session_binding_key', str_repeat('ab', 32));
        config()->set('session.secure', false);
        Cookie::flushQueuedCookies();
    }

    public function test_csrf_bootstrap_issues_proof_reusable_only_on_same_host(): void
    {
        $middleware = new EnsureTenantLoginClientProof;
        $csrf = Request::create('/sanctum/csrf-cookie', 'GET', [], [], [], [
            'HTTP_HOST' => 'alpha.core01.localhost',
        ]);
        $response = $middleware->handle($csrf, static fn () => new Response('', 204));

        self::assertSame(204, $response->getStatusCode());
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', (string) $csrf->attributes->get('tenant_login_client_hash'));
        $cookie = collect(Cookie::getQueuedCookies())->first(
            static fn ($queued) => $queued->getName() === 'daleel_login_client',
        );
        self::assertNotNull($cookie);
        self::assertTrue($cookie->isHttpOnly());
        self::assertSame('strict', $cookie->getSameSite());

        $login = Request::create('/api/v1/auth/login', 'POST', [], [
            'daleel_login_client' => $cookie->getValue(),
        ], [], ['HTTP_HOST' => 'alpha.core01.localhost']);
        $middleware->handle($login, static fn () => new Response('', 204));
        self::assertSame(
            $csrf->attributes->get('tenant_login_client_hash'),
            $login->attributes->get('tenant_login_client_hash'),
        );

        $crossHost = Request::create('/api/v1/auth/login', 'POST', [], [
            'daleel_login_client' => $cookie->getValue(),
        ], [], ['HTTP_HOST' => 'beta.core01.localhost']);
        $this->expectException(HttpException::class);
        $this->expectExceptionCode(0);
        $middleware->handle($crossHost, static fn () => new Response('', 204));
    }

    public function test_login_without_client_proof_fails_closed(): void
    {
        $this->expectException(HttpException::class);
        (new EnsureTenantLoginClientProof)->handle(
            Request::create('/api/v1/auth/login', 'POST', [], [], [], ['HTTP_HOST' => 'alpha.core01.localhost']),
            static fn () => new Response('', 204),
        );
    }
}
