<?php

namespace App\Providers;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Auth;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(
            \App\Modules\Identity\Application\TenantAuthorityAuthenticator::class,
            \App\Modules\Identity\Application\TenantStaffLoginService::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\TenantRuntimeConnectionProvider::class,
            \App\Modules\Identity\Application\LaravelTenantRuntimeConnectionProvider::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\RestrictedTenantProbeExecutor::class,
            \App\Modules\Identity\Application\LaravelRestrictedTenantProbeExecutor::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\TenantAuthorityRevoker::class,
            \App\Modules\Identity\Application\TenantAuthoritySessionService::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\TenantRuntimeIdentityAttestor::class,
            \App\Modules\Identity\Application\LaravelTenantRuntimeIdentityAttestor::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\RevokedTenantSessionVerifier::class,
            \App\Modules\Identity\Application\LaravelRevokedTenantSessionVerifier::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\F3CommittedWitnessObserver::class,
            \App\Modules\Identity\Application\LaravelF3CommittedWitnessObserver::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\F3AcceptanceFixtureOrchestrator::class,
            \App\Modules\Identity\Application\LaravelF3AcceptanceFixtureOrchestrator::class,
        );
        $this->app->bind(
            \App\Modules\Identity\Application\F3AcceptanceFixturePrewriteAttestor::class,
            \App\Modules\Identity\Application\LaravelF3AcceptanceFixturePrewriteAttestor::class,
        );
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Auth::provider('tenant-staff', static function ($app, array $config) {
            return new \App\Modules\Identity\Infrastructure\Persistence\TenantStaffUserProvider(
                $app['hash'],
                $config['model'],
            );
        });

        ResetPassword::createUrlUsing(static function ($user, string $token): string {
            return rtrim((string) config('identity.reset_url'), '?&').'?'.http_build_query([
                'token' => $token,
                'email' => $user->getEmailForPasswordReset(),
            ]);
        });

        RateLimiter::for('api', static fn (Request $request) => Limit::perMinute(60)
            ->by((string) ($request->user()?->getAuthIdentifier() ?? $request->ip() ?? 'unknown')));
    }
}
