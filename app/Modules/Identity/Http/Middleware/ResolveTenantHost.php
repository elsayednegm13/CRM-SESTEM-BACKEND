<?php

namespace App\Modules\Identity\Http\Middleware;

use App\Modules\Identity\Application\TenantHostResolver;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Closure;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;

final class ResolveTenantHost
{
    public function handle(Request $request, Closure $next): Response
    {
        if (config('identity.tenant_auth_client_enabled') !== true
            || ! in_array(config('app.env'), ['local', 'testing'], true)) {
            throw TenantAccessException::objectNotFound();
        }

        try {
            // Laravel/Symfony applies forwarded-host values only for configured
            // trusted proxies. No proxy is trusted by default in this foundation.
            $context = app(TenantHostResolver::class)->resolve($request->getHost());
        } catch (InvalidArgumentException) {
            throw TenantAccessException::objectNotFound();
        }

        $request->attributes->set('tenant_host_context', $context);

        return $next($request);
    }
}
