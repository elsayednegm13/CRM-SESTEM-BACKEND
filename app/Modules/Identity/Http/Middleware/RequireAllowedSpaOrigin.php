<?php

namespace App\Modules\Identity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class RequireAllowedSpaOrigin
{
    public function handle(Request $request, Closure $next): Response
    {
        $origin = $request->headers->get('Origin');
        if (! is_string($origin) || ! in_array($origin, config('cors.allowed_origins', []), true)) {
            abort(403);
        }

        return $next($request);
    }
}
