<?php

namespace App\Modules\Identity\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

/** A short-lived host-bound proof that survives Laravel's pre-auth session rotation. */
final class EnsureTenantLoginClientProof
{
    private const COOKIE = 'daleel_login_client';

    private const MAX_AGE_SECONDS = 900;

    public function handle(Request $request, Closure $next): Response
    {
        $csrfBootstrap = $request->is('sanctum/csrf-cookie');
        $login = $request->is('api/v1/auth/login');
        if (! $csrfBootstrap && ! $login) {
            return $next($request);
        }

        $key = $this->bindingKey();
        if ($key === null) {
            return response()->json(['error' => 'runtime_unavailable'], 503);
        }

        $host = strtolower($request->getHost());
        $token = $request->cookie(self::COOKIE);
        $clientHash = is_string($token) ? $this->validate($token, $host, $key) : null;

        if ($clientHash === null && $csrfBootstrap) {
            $token = $this->issue($host, $key);
            $clientHash = hash_hmac('sha256', "login-client-proof\0".$token, $key);
            Cookie::queue(Cookie::make(
                self::COOKIE,
                $token,
                (int) ceil(self::MAX_AGE_SECONDS / 60),
                '/',
                null,
                (bool) config('session.secure'),
                true,
                false,
                'strict',
            ));
        }

        if ($clientHash === null) {
            abort(419, 'Login client proof is unavailable or expired.');
        }

        $request->attributes->set('tenant_login_client_hash', $clientHash);

        return $next($request);
    }

    private function issue(string $host, string $key): string
    {
        $issuedAt = (string) time();
        $nonce = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $mac = hash_hmac('sha256', "login-client-v1\0{$host}\0{$issuedAt}\0{$nonce}", $key);

        return "v1.{$issuedAt}.{$nonce}.{$mac}";
    }

    private function validate(string $token, string $host, string $key): ?string
    {
        if (preg_match('/^v1\.([0-9]{10})\.([A-Za-z0-9_-]{43})\.([a-f0-9]{64})$/D', $token, $parts) !== 1) {
            return null;
        }
        $age = time() - (int) $parts[1];
        if ($age < 0 || $age > self::MAX_AGE_SECONDS) {
            return null;
        }
        $expected = hash_hmac('sha256', "login-client-v1\0{$host}\0{$parts[1]}\0{$parts[2]}", $key);
        if (! hash_equals($expected, $parts[3])) {
            return null;
        }

        return hash_hmac('sha256', "login-client-proof\0".$token, $key);
    }

    private function bindingKey(): ?string
    {
        $value = config('core_sql.session_binding_key');
        if (! is_string($value) || preg_match('/^[a-f0-9]{64}$/D', $value) !== 1) {
            return null;
        }
        $key = hex2bin($value);

        return is_string($key) ? $key : null;
    }
}
