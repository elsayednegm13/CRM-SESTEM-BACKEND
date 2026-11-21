<?php

namespace App\Modules\Shared\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** HTTP ingress gate for two isolated processes using the same Laravel tree. */
final class CoreRuntimeBoundary
{
    public function handle(Request $request, Closure $next): Response
    {
        $mode = config('core_runtime.mode');
        $trusted = config('core_sql.trusted_tenant_login');
        $legacy = config('core_sql.legacy_tenant_login');
        $owner = config('core_runtime.owner_login');
        if (! $this->roleName($trusted) || ! $this->roleName($legacy)
            || ! $this->roleName($owner) || count(array_unique([$trusted, $legacy, $owner])) !== 3
            || ! is_string(config('app.key')) || config('app.key') === '') {
            return $this->unavailable('IDENTITY_CONFIGURATION');
        }

        $baseHost = config('core_runtime.base_host');
        $legacyHost = config('core_runtime.legacy_host');
        $rawHost = $request->server->get('HTTP_HOST');
        if (! is_string($baseHost) || ! preg_match('/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/D', $baseHost)
            || ! is_string($legacyHost) || ! preg_match('/^[a-z0-9]+(?:[.-][a-z0-9]+)*$/D', $legacyHost)
            || ! is_string($rawHost) || ! preg_match('/^([a-z0-9]+(?:[.-][a-z0-9]+)*)(?::[0-9]{1,5})?$/D', $rawHost, $hostMatch)
            || $request->headers->has('Forwarded') || $request->headers->has('X-Forwarded-Host')) {
            return $this->unavailable('HOST_CONFIGURATION');
        }
        $host = $hostMatch[1];
        if (config('session.domain') !== null) {
            return $this->unavailable('SHARED_COOKIE_DOMAIN');
        }

        $connections = (array) config('database.connections', []);
        $pgLogins = [];
        foreach ($connections as $name => $connection) {
            if (! is_array($connection) || ($connection['driver'] ?? null) !== 'pgsql') {
                continue;
            }
            $username = $connection['username'] ?? null;
            if (is_string($username) && $username !== '') {
                $pgLogins[] = $username;
            }
            if (is_string($connection['url'] ?? null) && $connection['url'] !== '') {
                return $this->unavailable('DATABASE_URL_PRESENT');
            }
            $password = $connection['password'] ?? null;
            if (is_string($password) && $password !== ''
                && ($username === null || $username === ''
                    || ($mode === 'legacy' && $name !== 'pgsql_tenant_runtime'))) {
                return $this->unavailable('DATABASE_PASSWORD_WITHOUT_IDENTITY');
            }
        }
        if (in_array($owner, $pgLogins, true)) {
            return $this->unavailable('OWNER_CREDENTIAL_PRESENT');
        }

        if ($mode === 'trusted') {
            if (config('database.default') !== 'pgsql_provider') {
                return $this->unavailable('TRUSTED_DEFAULT_CONNECTION');
            }
            if (config('database.connections.pgsql_tenant_runtime.username') !== $trusted) {
                return $this->unavailable('TRUSTED_TENANT_IDENTITY');
            }
            if (! $this->roleName(config('database.connections.pgsql_provider.username'))) {
                return $this->unavailable('TRUSTED_PROVIDER_IDENTITY');
            }
            if (in_array($legacy, $pgLogins, true)) {
                return $this->unavailable('TRUSTED_LEGACY_CREDENTIAL_PRESENT');
            }
            if ($host === $legacyHost || ! str_ends_with($host, '.'.$baseHost)) {
                return $this->unavailable('TRUSTED_HOST');
            }
            return $next($request);
        }

        if ($mode === 'legacy') {
            if (config('database.default') !== 'pgsql_tenant_runtime'
                || config('database.connections.pgsql_tenant_runtime.username') !== $legacy
                || array_diff($pgLogins, [$legacy]) !== []
                || $host !== $legacyHost) {
                return $this->unavailable('LEGACY_PROCESS_CONTRACT');
            }
            // The legacy process has no company/provider authority. Routes that
            // need tenant data are moved to trusted only after dedicated review.
            if (! $request->is('api/v1/health/live')) {
                return response()->json(['error' => 'not_found'], 404);
            }
            return $next($request);
        }

        return $this->unavailable('UNKNOWN_RUNTIME_MODE');
    }

    private function roleName(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[a-z_][a-z0-9_]{2,62}$/D', $value) === 1;
    }

    private function unavailable(string $reason): Response
    {
        logger()->warning('Core runtime boundary rejected the request.', [
            'reason' => $reason,
        ]);

        return response()->json(['error' => 'runtime_unavailable'], 503);
    }
}
