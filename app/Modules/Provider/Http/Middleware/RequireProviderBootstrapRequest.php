<?php

namespace App\Modules\Provider\Http\Middleware;


use App\Modules\Provider\Domain\ProviderBootstrapPolicy;
use Closure;
use Illuminate\Http\Request;

use Symfony\Component\HttpFoundation\Response;

final class RequireProviderBootstrapRequest
{
    public function __construct(private readonly ProviderBootstrapPolicy $policy) {}

    public function handle(Request $request, Closure $next): Response
    {
        $settings = config('provider.bootstrap', []);
        $this->policy->assertConfigured($settings, time());
        $this->policy->assertTransport($request->isSecure(), $request->getHost(),
            (string) $request->headers->get('Origin'), app()->environment('local'),
            ($settings['allow_loopback_http'] ?? false) === true);

        return $next($request);
    }
}
