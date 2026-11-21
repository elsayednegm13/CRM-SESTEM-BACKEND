<?php

namespace App\Modules\Provider\Http\Middleware;

use App\Modules\Provider\Application\ProviderAuthorizationService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class ValidateProviderSession
{
    public function __construct(private readonly ProviderAuthorizationService $authorization) {}

    public function handle(Request $request, Closure $next): Response
    {
        $request->attributes->set('provider_context', $this->authorization->current($request));
        try {
            return $next($request);
        } finally {
            $request->attributes->remove('provider_context');
        }
    }
}
