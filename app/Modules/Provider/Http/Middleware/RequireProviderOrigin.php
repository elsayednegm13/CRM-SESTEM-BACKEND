<?php

namespace App\Modules\Provider\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class RequireProviderOrigin
{
    public function handle(Request $request, Closure $next): Response
    {
        $host = $request->server->get('HTTP_HOST');
        $allowedHosts = config('provider.api_hosts', []);
        if (! is_string($host) || $host === '' || str_contains($host, ',')
            || ! in_array(strtolower($host), $allowedHosts, true)) {
            abort(403);
        }

        $origin = $request->headers->get('Origin');
        if (! is_string($origin) || ! in_array($origin, config('provider.allowed_origins', []), true)
            || ! in_array($origin, config('cors.allowed_origins', []), true)) {
            abort(403);
        }
        return $next($request);
    }
}
