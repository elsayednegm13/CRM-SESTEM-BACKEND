<?php

namespace Tests\Unit\Modules\Provider;

use App\Modules\Provider\Application\ProviderAuthenticationService;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Auth;
use Mockery;
use RuntimeException;
use Tests\TestCase;

final class ProviderLogoutFailureTest extends TestCase
{
    public function test_failed_authority_revoke_still_clears_and_rotates_local_provider_session(): void
    {
        config()->set('core_sql.provider_authority_enabled', true);
        config()->set('core_sql.session_binding_key', str_repeat('a', 64));
        config()->set('database.connections.pgsql_provider_issuer.username', '');

        $session = new Store('provider-logout-fault', new ArraySessionHandler(120));
        $session->start();
        $session->put([
            'provider.authenticated_at' => time(),
            'provider.auth_version' => 1,
            'provider.authority_generation' => '019a9f00-0000-7000-8000-000000000099',
            'provider.authority_receipts' => ['proof' => 'must-be-cleared'],
            'tenant.session.sentinel' => 'preserved',
        ]);
        $before = $session->getId();
        $request = Request::create('/api/v1/super/auth/logout', 'POST');
        $request->setLaravelSession($session);

        $guard = Mockery::mock();
        $guard->shouldReceive('logout')->once();
        Auth::shouldReceive('guard')->once()->with('provider')->andReturn($guard);

        try {
            app(ProviderAuthenticationService::class)->logout($request);
            self::fail('The authority revocation failure was swallowed.');
        } catch (RuntimeException $exception) {
            self::assertSame('Provider authority issuer is not configured.', $exception->getMessage());
        }

        self::assertNotSame($before, $session->getId());
        self::assertFalse($session->has('provider.authenticated_at'));
        self::assertFalse($session->has('provider.auth_version'));
        self::assertFalse($session->has('provider.authority_generation'));
        self::assertFalse($session->has('provider.authority_receipts'));
        self::assertSame('preserved', $session->get('tenant.session.sentinel'));
    }
}
