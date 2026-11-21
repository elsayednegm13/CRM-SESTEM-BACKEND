<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * SECURITY-F06-LARAVEL-IMPLEMENT-01: read-only revalidation of the server-side
 * session tuple (tenant/host/staff/membership/auth_version/authorization_version)
 * against a bootstrap connection that is DISTINCT from pgsql_tenant_runtime and
 * DISTINCT from the per-actor connection ActorConnectionFactory switches to.
 *
 * This connection authenticates as daleel_f06i01_bootstrap_client (sandbox-only)
 * and only has EXECUTE on the narrow SECURITY DEFINER lookup function; it has no
 * direct table grants and cannot itself be used to read/write leads.
 *
 * Known, documented limitation (T4b, OPEN, out of scope here): the bootstrap
 * lookup is itself SQL reachable under a single shared bootstrap credential, so
 * it does not by itself defend against a PHP-process-level compromise that can
 * open arbitrary database credentials (PHP_MULTI_CREDENTIAL_COMPROMISE_RISK=OPEN).
 */
final class TrustedActorBootstrapVerifier
{
    private const CONNECTION = 'pgsql_f06_bootstrap';

    /** Returns the mapped SQL role name for an ACTIVE, version-matched tuple, or null. */
    public function resolveSqlRoleName(TenantHostContext $host, string $userId, string $membershipId, int $authVersion, int $authorizationVersion): ?string
    {
        $configuration = config('database.connections.'.self::CONNECTION);
        foreach (['host', 'database', 'username', 'password'] as $key) {
            if (! is_array($configuration) || ! is_string($configuration[$key] ?? null) || trim($configuration[$key]) === '') {
                throw new RuntimeException('The F06 bootstrap connection is not configured; refusing to run (fail closed).');
            }
        }

        // SECURITY-F06-LARAVEL-IMPLEMENT-02: each isolated sandbox round creates its
        // own uniquely-named lookup function (f06i01_bootstrap_lookup,
        // f06i02_bootstrap_lookup, ...); the name is config-driven so this class
        // does not need editing again for the next round's sandbox.
        $function = config('f06_actor_sql.bootstrap_lookup_function', 'public.f06i01_bootstrap_lookup');
        if (! is_string($function) || ! preg_match('/^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/D', $function)) {
            throw new RuntimeException('The F06 bootstrap lookup function name is not configured safely; refusing to run.');
        }

        $row = DB::connection(self::CONNECTION)->selectOne(
            "SELECT sql_role_name FROM {$function}(?, ?, ?, ?, ?) LIMIT 1",
            [$host->tenantId, $userId, $membershipId, $authVersion, $authorizationVersion],
        );

        return $row->sql_role_name ?? null;
    }
}
