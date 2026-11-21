<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\TenantAcceptanceRequestBinder;
use Illuminate\Auth\SessionGuard;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use ReflectionProperty;
use Tests\TestCase;

final class TenantAcceptanceRequestBinderTest extends TestCase
{
    public function test_binds_same_request_to_container_and_session_guard_then_restores(): void
    {
        $previous = app('request');
        $request = Request::create('https://a.test/api/v1/auth/login', 'POST');
        $session = new Store('binder', new ArraySessionHandler(60));
        $session->start();
        $request->setLaravelSession($session);

        (new TenantAcceptanceRequestBinder)->run($request, function () use ($request): void {
            self::assertSame($request, app('request'));
            $guard = Auth::guard('tenant_staff');
            self::assertInstanceOf(SessionGuard::class, $guard);
            $property = new ReflectionProperty($guard, 'request');
            self::assertSame($request, $property->getValue($guard));
            $before = $request->session()->getId();
            $request->session()->migrate(true);
            self::assertNotSame($before, $request->session()->getId());
        });

        self::assertSame($previous, app('request'));
    }
}
