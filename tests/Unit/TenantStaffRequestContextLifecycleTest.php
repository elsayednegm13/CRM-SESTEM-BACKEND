<?php

namespace Tests\Unit;

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Http\Middleware\TenantStaffRequestContext;
use Illuminate\Database\Connection;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Mockery;
use Tests\TestCase;

final class TenantStaffRequestContextLifecycleTest extends TestCase
{
    public function test_rendered_login_failure_rolls_back_before_revoking_pending_authority(): void
    {
        config(['f06_actor_sql.enabled' => false]);

        $request = Request::create('/api/v1/auth/login', 'POST');
        $session = new Store('secfix04-lifecycle', new ArraySessionHandler(120));
        $session->start();
        $request->setLaravelSession($session);
        $route = new Route(['POST'], '/api/v1/auth/login', static fn () => null);
        $route->name('api.v1.auth.login');
        $request->setRouteResolver(static fn () => $route);
        $request->attributes->set('tenant_host_context', new TenantHostContext(
            (string) Str::uuid(), 'secfix04-a', 'secfix04-a.secfix04.localhost',
            'secfix04.localhost', 'LOCAL_TEST',
        ));

        $runtime = Mockery::mock(Connection::class);
        $authConnection = Mockery::mock(Connection::class);
        $guard = Mockery::mock();
        $guard->shouldReceive('logout')->twice();
        Auth::shouldReceive('guard')->with('tenant_staff')->twice()->andReturn($guard);

        DB::shouldReceive('connection')->with('pgsql_tenant_runtime')->once()->andReturn($runtime);
        $runtime->shouldReceive('beginTransaction')->once()->ordered('lifecycle');
        $runtime->shouldReceive('selectOne')->times(3)->ordered('lifecycle');
        $runtime->shouldReceive('rollBack')->once()->ordered('lifecycle');
        DB::shouldReceive('connection')->with('pgsql_tenant_auth')->once()->ordered('lifecycle')->andReturn($authConnection);
        $authConnection->shouldReceive('selectOne')
            ->once()
            ->with(
                'SELECT public.core01_tenant_authority_revoke_session(?, ?::uuid)',
                [str_repeat('a', 64), '11111111-1111-4111-8111-111111111111'],
            )
            ->ordered('lifecycle')
            ->andReturn((object) []);
        $runtime->shouldNotReceive('commit');

        $response = (new TenantStaffRequestContext)->handle(
            $request,
            static function (Request $request): JsonResponse {
                $request->attributes->set('tenant_staff_authority_cleanup', [
                    'hash' => str_repeat('a', 64),
                    'generation' => '11111111-1111-4111-8111-111111111111',
                ]);

                return new JsonResponse(['error' => 'rendered'], 403);
            },
        );

        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($request->session()->has('identity.tenant_staff'));
        self::assertFalse($request->session()->has('identity.tenant_authority_generation'));
    }
}
