<?php

namespace App\Modules\Tenancy\Http\Middleware;

use App\Modules\Tenancy\Application\ResolveTenantContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class ResolveCompanyContext
{
    public function __construct(private readonly ResolveTenantContext $resolver)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        if ($request->headers->has('X-Tenant-ID')) {
            throw TenantAccessException::selectorNotAllowed();
        }

        $user = $request->user('web');
        if (! $user) {
            throw TenantAccessException::contextRequired();
        }

        $requestId = $request->attributes->get('request_id');
        if (! is_string($requestId)) {
            throw TenantAccessException::contextRequired();
        }

        $context = $this->resolver->resolve((string) $user->getKey(), (int) $user->auth_version, $requestId);
        $request->attributes->set('tenant_context', $context);

        try {
            return $next($request);
        } finally {
            $request->attributes->remove('tenant_context');
        }
    }
}
