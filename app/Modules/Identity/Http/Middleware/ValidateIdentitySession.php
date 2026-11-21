<?php

namespace App\Modules\Identity\Http\Middleware;

use App\Modules\Identity\Domain\Enums\UserStatus;
use App\Modules\Identity\Domain\Exceptions\AuthSessionExpiredException;
use App\Modules\Identity\Infrastructure\Persistence\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

final class ValidateIdentitySession
{
    public function handle(Request $request, Closure $next): Response
    {
        $sessionVersion = $request->session()->get('identity.auth_version');
        $startedAt = $request->session()->get('identity.authenticated_at');
        $authenticated = Auth::guard('web')->user();
        if (! $authenticated) {
            throw new AuthenticationException;
        }
        $current = $authenticated
            ? User::query()->whereKey($authenticated->getKey())->first(['id', 'auth_version', 'status'])
            : null;
        $absoluteLifetime = max(1, (int) config('identity.absolute_session_lifetime', 28800));

        if (! $current
            || $current->status !== UserStatus::ACTIVE
            || ! is_numeric($sessionVersion)
            || (int) $sessionVersion !== $current->auth_version
            || ! is_numeric($startedAt)
            || now()->timestamp - (int) $startedAt >= $absoluteLifetime) {
            Auth::guard('web')->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            throw new AuthSessionExpiredException;
        }

        return $next($request);
    }
}
