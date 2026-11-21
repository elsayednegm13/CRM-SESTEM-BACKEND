<?php

namespace App\Modules\Identity\Http\Middleware;

use App\Modules\Identity\Application\ActorConnectionFactory;
use App\Modules\Identity\Application\ActorSqlIdentityResolver;
use App\Modules\Identity\Application\TenantStaffContextGuard;
use App\Modules\Identity\Application\TenantAuthoritySessionService;
use App\Modules\Identity\Application\TrustedActorBootstrapVerifier;
use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class TenantStaffRequestContext
{
    public function handle(Request $request, Closure $next): Response
    {
        $host = $request->attributes->get('tenant_host_context');
        if (! $host instanceof TenantHostContext) {
            throw TenantAccessException::contextRequired();
        }

        // SECURITY-F06-LARAVEL-IMPLEMENT-01: default-OFF. When the flag is false
        // (the default, and the only state outside this explicit sandbox slice),
        // execution falls straight through to the unchanged legacy path below --
        // same connection, same transaction order, same behavior, byte-for-byte.
        if ($this->f06Enabled()) {
            // The F06 actor-SQL path has a different identity proof and cannot
            // silently bypass CORE-01's durable tenant authority contract.
            if ($request->session()->get('identity.tenant_authority_generation') !== null
                || $request->session()->get('identity.tenant_staff') !== null) {
                throw TenantAccessException::contextRequired();
            }
            return $this->handleWithActorSqlIdentity($request, $next, $host);
        }

        $authoritySessions = app(TenantAuthoritySessionService::class);
        if ($request->routeIs('api.v1.auth.login')) {
            // Re-login cleanup must finish before the runtime transaction opens.
            $authoritySessions->revoke($request);
            $request->session()->forget('identity.tenant_staff');
            $request->session()->forget('identity.tenant_authority_generation');
            \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
        }

        /** @var Connection $connection */
        $connection = DB::connection('pgsql_tenant_runtime');
        $connection->beginTransaction();
        $invalidAuthority = null;
        $logoutAuthority = null;

        try {
            // Reset prior state defensively; SET LOCAL is still cleared at transaction end.
            foreach (['app.context_mode', 'app.tenant_id', 'app.user_id'] as $key) {
                $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', [$key, '']);
            }

            $stored = $request->session()->get('identity.tenant_staff');
            if (! $request->routeIs('api.v1.auth.login') && $stored !== null) {
                try {
                    if (! is_array($stored)) {
                        throw TenantAccessException::contextRequired();
                    }
                    $context = app(TenantStaffContextGuard::class)->activateFromSession($host, $stored, $request);
                    $request->attributes->set('tenant_staff_context', $context);
                } catch (TenantAccessException) {
                    foreach (['app.context_mode', 'app.tenant_id', 'app.user_id'] as $key) {
                        $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', [$key, '']);
                    }
                    $invalidAuthority = $authoritySessions->snapshot($request);
                    throw new AuthenticationException;
                }
            }

            $logoutAuthority = $authoritySessions->snapshot($request);
            $response = $next($request);

            // Laravel may render a controller/service exception into an HTTP
            // response inside the pipeline instead of rethrowing it here. A
            // registered authority is successful only after the login service
            // sets its explicit success marker; otherwise rollback before revoke.
            $pendingCleanup = $request->attributes->get('tenant_staff_authority_cleanup');
            if (is_array($pendingCleanup)
                && $request->attributes->get('tenant_staff_new_authority') !== true) {
                $connection->rollBack();
                try {
                    $authoritySessions->revokeHash(
                        (string) ($pendingCleanup['hash'] ?? ''),
                        (string) ($pendingCleanup['generation'] ?? '')
                    );
                } finally {
                    \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
                    $request->session()->forget('identity.tenant_staff');
                    $request->session()->forget('identity.tenant_authority_generation');
                }

                return $response;
            }
            $connection->commit();

            if ($request->attributes->get('tenant_staff_logout_requested') === true) {
                if ($logoutAuthority !== null) {
                    $authoritySessions->revokeHash($logoutAuthority['hash'], $logoutAuthority['generation']);
                }
                \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
                $request->session()->forget('identity.tenant_staff');
                $request->session()->forget('identity.tenant_authority_generation');
                $request->session()->invalidate();
                $request->session()->regenerateToken();
            }
            $request->attributes->remove('tenant_staff_authority_cleanup');

            return $response;
        } catch (Throwable $exception) {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
            $cleanupAuthority = $request->attributes->get('tenant_staff_authority_cleanup');
            if (is_array($cleanupAuthority)) {
                try {
                    $authoritySessions->revokeHash(
                        (string) ($cleanupAuthority['hash'] ?? ''),
                        (string) ($cleanupAuthority['generation'] ?? '')
                    );
                } finally {
                    \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
                    $request->session()->forget('identity.tenant_staff');
                    $request->session()->forget('identity.tenant_authority_generation');
                }
            } elseif ($invalidAuthority !== null) {
                try {
                    $authoritySessions->revokeHash($invalidAuthority['hash'], $invalidAuthority['generation']);
                } finally {
                    \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
                    $request->session()->forget('identity.tenant_staff');
                    $request->session()->forget('identity.tenant_authority_generation');
                }
            }
            throw $exception;
        }
    }

    private function f06Enabled(): bool
    {
        if (! (bool) config('f06_actor_sql.enabled')) {
            return false;
        }

        $allowed = (array) config('f06_actor_sql.allow_env', []);

        // Fail closed: the flag has no effect unless APP_ENV is explicitly
        // whitelisted for this slice (sandbox/testing only, never production).
        return in_array(app()->environment(), $allowed, true);
    }

    /**
     * Actor-SQL-identity path (flag ON, sandbox only). Login/session/host
     * validation is identical to the legacy path; the difference is: (1) tenant/
     * staff/membership revalidation happens via TrustedActorBootstrapVerifier on a
     * connection distinct from pgsql_tenant_runtime, BEFORE any transaction is
     * opened; (2) pgsql_tenant_runtime is then switched, via ActorConnectionFactory,
     * to a real PostgreSQL LOGIN unique to the membership, and ONLY THEN does the
     * business transaction begin; (3) the actor connection is unconditionally torn
     * down in a finally block so it cannot leak into a later request on the same
     * PHP-FPM worker (GATE-06 / SESSION_REUSE).
     */
    private function handleWithActorSqlIdentity(Request $request, Closure $next, TenantHostContext $host): Response
    {
        if ($request->routeIs('api.v1.auth.login')) {
            // Login itself never runs under an actor-switched connection; it has no
            // membership to resolve yet. Session clearing only, no DB identity switch.
            $request->session()->forget('identity.tenant_staff');
            \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
        }

        $stored = $request->session()->get('identity.tenant_staff');
        $context = null;
        $factory = new ActorConnectionFactory;

        try {
            if ($stored !== null && ! $request->routeIs('api.v1.auth.login')) {
                if (! is_array($stored)) {
                    throw new AuthenticationException;
                }

                try {
                    [$userId, $membershipId, $authVersion, $authorizationVersion] =
                        app(TenantStaffContextGuard::class)->validateStoredShape($host, $stored);
                } catch (TenantAccessException) {
                    $request->session()->forget('identity.tenant_staff');
                    \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
                    throw new AuthenticationException;
                }

                $sqlRoleName = app(TrustedActorBootstrapVerifier::class)
                    ->resolveSqlRoleName($host, $userId, $membershipId, $authVersion, $authorizationVersion);

                // Missing/suspended/version-mismatched/unmapped membership denies
                // BEFORE any data SQL and WITHOUT falling back to the shared runtime
                // credential (GATE-06).
                if ($sqlRoleName === null) {
                    $request->session()->forget('identity.tenant_staff');
                    \Illuminate\Support\Facades\Auth::guard('tenant_staff')->logout();
                    throw new AuthenticationException;
                }

                $password = app(ActorSqlIdentityResolver::class)->passwordFor($sqlRoleName);
                $factory->switchTo($sqlRoleName, $password);

                $context = new TenantStaffContext($host->tenantId, $host->hostname, $userId, $membershipId, $authVersion, $authorizationVersion);
            }

            /** @var Connection $connection */
            $connection = DB::connection('pgsql_tenant_runtime');
            $connection->beginTransaction();

            try {
                foreach (['app.context_mode', 'app.tenant_id', 'app.user_id'] as $key) {
                    $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', [$key, '']);
                }
                if ($context instanceof TenantStaffContext) {
                    $request->attributes->set('tenant_staff_context', $context);
                    // Defensive only: RLS in this slice is keyed on session_user, not
                    // this GUC. Kept so unmodified app-layer code that still reads
                    // app.tenant_id for ALL_TENANT/ASSIGNED/SELF filtering keeps working.
                    $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', ['app.context_mode', 'TENANT']);
                    $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', ['app.tenant_id', $context->tenantId]);
                    $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', ['app.user_id', $context->userId]);
                }

                $response = $next($request);
                $connection->commit();

                return $response;
            } catch (Throwable $exception) {
                if ($connection->transactionLevel() > 0) {
                    $connection->rollBack();
                }
                throw $exception;
            }
        } finally {
            // Unconditional: runs whether the request succeeded, threw during
            // validation, or threw inside the transaction. transactionLevel() is
            // guaranteed 0 here because the inner try/catch above always resolves
            // the transaction (commit or rollback) before this finally runs.
            $factory->reset();
        }
    }
}
