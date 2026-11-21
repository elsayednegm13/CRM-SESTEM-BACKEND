<?php

declare(strict_types=1);

namespace App\Modules\Provider\Http\Middleware;

use App\Modules\Provider\Application\ProviderAuthorizationService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Password-authenticated self-service boundary for MFA status/enrollment only.
 * It never grants step-up or access to Provider business/issuer operations.
 */
final class ValidateProviderSecuritySettingsSession
{
    public function __construct(private readonly ProviderAuthorizationService $authorization) {}

    public function handle(Request $request, Closure $next): Response
    {
        $request->attributes->set('provider_context', $this->authorization->currentForSecuritySettings($request));
        try {
            return $next($request);
        } finally {
            $request->attributes->remove('provider_context');
        }
    }
}
