<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Identity\Domain\TenantStaffContext;
use App\Modules\Tenancy\Domain\TenantAccessException;
use Illuminate\Database\Connection;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

final class TenantStaffContextGuard
{
    public function activateAfterCredentialCheck(TenantHostContext $host, object $lookup, Request $request, string $generation): TenantStaffContext
    {
        if (! hash_equals($host->tenantId, (string) $lookup->tenant_id)
            || ! Str::isUuid((string) $lookup->staff_user_id)
            || ! Str::isUuid((string) $lookup->membership_id)) {
            throw TenantAccessException::contextRequired();
        }

        [$context, $connection] = $this->bindAndRevalidate(
            $host,
            (string) $lookup->staff_user_id,
            (string) $lookup->membership_id,
            (int) $lookup->auth_version,
            (int) $lookup->membership_authorization_version,
            app(TenantAuthoritySessionService::class)->sessionHash($request, $generation),
            $generation,
        );
        $request->attributes->set('tenant_staff_runtime_connection_id', spl_object_id($connection));

        return $context;
    }

    public function activateFromSession(TenantHostContext $host, array $stored, Request $request): TenantStaffContext
    {
        [$userId, $membershipId, $authVersion, $authorizationVersion] = $this->validateStoredShape($host, $stored);
        $generation = $stored['authority_generation'] ?? null;
        if (! is_string($generation) || ! Str::isUuid($generation)) {
            throw TenantAccessException::contextRequired();
        }

        [$context, $connection] = $this->bindAndRevalidate($host, $userId, $membershipId, $authVersion, $authorizationVersion,
            app(TenantAuthoritySessionService::class)->sessionHash($request, $generation), $generation);
        $request->attributes->set('tenant_staff_runtime_connection_id', spl_object_id($connection));

        return $context;
    }

    /**
     * Pure, no-SQL validation of the server-side session tuple's shape against the
     * resolved host context. Extracted so SECURITY-F06-LARAVEL-IMPLEMENT-01's actor-SQL
     * path (flag ON) can reuse the exact same tuple-shape rule and then revalidate the
     * tuple through TrustedActorBootstrapVerifier instead of the shared runtime
     * connection -- without duplicating or silently diverging the validation rule.
     *
     * @return array{0: string, 1: string, 2: int, 3: int} [userId, membershipId, authVersion, authorizationVersion]
     */
    public function validateStoredShape(TenantHostContext $host, array $stored): array
    {
        $tenantId = $stored['tenant_id'] ?? null;
        $hostname = $stored['hostname'] ?? null;
        $userId = $stored['user_id'] ?? null;
        $membershipId = $stored['membership_id'] ?? null;
        $authVersion = $stored['auth_version'] ?? null;
        $authorizationVersion = $stored['authorization_version'] ?? null;

        if (! is_string($tenantId) || ! hash_equals($host->tenantId, $tenantId)
            || ! is_string($hostname) || ! hash_equals($host->hostname, $hostname)
            || ! is_string($userId) || ! Str::isUuid($userId)
            || ! is_string($membershipId) || ! Str::isUuid($membershipId)
            || ! is_int($authVersion) || $authVersion < 1
            || ! is_int($authorizationVersion) || $authorizationVersion < 1) {
            throw TenantAccessException::contextRequired();
        }

        return [$userId, $membershipId, $authVersion, $authorizationVersion];
    }

    /** @return array{0: TenantStaffContext, 1: Connection} */
    private function bindAndRevalidate(
        TenantHostContext $host,
        string $userId,
        string $membershipId,
        int $authVersion,
        int $authorizationVersion,
        ?string $sessionHash = null,
        ?string $sessionGeneration = null,
    ): array {
        $configuration = config('database.connections.pgsql_tenant_runtime');
        foreach (['host', 'database', 'username', 'password'] as $key) {
            if (! is_array($configuration) || ! is_string($configuration[$key] ?? null) || trim($configuration[$key]) === '') {
                throw new LogicException('The tenant runtime connection is not configured.');
            }
        }
        /** @var Connection $connection */
        $connection = DB::connection('pgsql_tenant_runtime');
        if ($connection->transactionLevel() < 1) {
            throw TenantAccessException::contextRequired();
        }

        // Existing tenant policies admit only TENANT. The v1 credential bridge
        // is separately marked and verified by the signed-boundary function.
        $this->set($connection, 'app.context_mode', 'TENANT');
        $this->set($connection, 'app.tenant_id', $host->tenantId);
        $this->set($connection, 'app.user_id', $userId);
        app(CoreSqlContextSigner::class)->bind($connection, $host, $userId,
            $membershipId, $authVersion, $authorizationVersion, $sessionHash, $sessionGeneration);

        $tenant = $connection->selectOne(
            'SELECT id, status FROM public.tenants WHERE id = ?',
            [$host->tenantId],
        );
        $staff = $connection->selectOne(
            'SELECT id, tenant_id, status, auth_version FROM public.tenant_staff_users WHERE tenant_id = ? AND id = ?',
            [$host->tenantId, $userId],
        );
        $membership = $connection->selectOne(
            'SELECT id, tenant_id, staff_user_id, status, authorization_version FROM public.tenant_staff_memberships WHERE tenant_id = ? AND id = ? AND staff_user_id = ?',
            [$host->tenantId, $membershipId, $userId],
        );

        if (! $tenant || $tenant->status !== 'ACTIVE'
            || ! $staff || $staff->tenant_id !== $host->tenantId
            || $staff->status !== 'ACTIVE' || (int) $staff->auth_version !== $authVersion
            || ! $membership || $membership->status !== 'ACTIVE'
            || $membership->tenant_id !== $host->tenantId || $membership->staff_user_id !== $userId
            || (int) $membership->authorization_version !== $authorizationVersion) {
            throw TenantAccessException::contextRequired();
        }

        return [new TenantStaffContext($host->tenantId, $host->hostname, $userId, $membershipId, $authVersion, $authorizationVersion), $connection];
    }

    private function set(Connection $connection, string $key, string $value): void
    {
        $connection->selectOne('SELECT pg_catalog.set_config(?, ?, true)', [$key, $value]);
    }
}
