<?php

namespace App\Modules\Identity\Http\Middleware;

use App\Modules\Identity\Domain\Exceptions\AuthSessionExpiredException;
use App\Modules\Identity\Domain\TenantStaffContext;
use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

final class ValidateTenantStaffSession
{
    public function handle(Request $request, Closure $next): Response
    {
        $context = $request->attributes->get('tenant_staff_context');
        $startedAt = $request->session()->get('identity.tenant_staff.authenticated_at');
        $user = Auth::guard('tenant_staff')->user();
        $absoluteLifetime = max(1, (int) config('identity.absolute_session_lifetime', 28800));

        if (! $context instanceof TenantStaffContext || ! $user
            || ! hash_equals($context->userId, (string) $user->getAuthIdentifier())
            || ! is_int($startedAt) || $startedAt <= 0 || $startedAt > now()->timestamp
            || now()->timestamp - $startedAt >= $absoluteLifetime) {
            Auth::guard('tenant_staff')->logout();
            $request->session()->forget('identity.tenant_staff');
            throw $user ? new AuthSessionExpiredException : new AuthenticationException;
        }

        return $next($request);
    }
}
