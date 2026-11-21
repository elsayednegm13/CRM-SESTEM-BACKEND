<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\RestrictedTenantProbeCleanupException;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use LogicException;
use Throwable;

/**
 * Acceptance-only committed-witness observer. It has no route and accepts no SQL.
 * Every data read is performed as the authenticated observer staff member on the
 * already bound pgsql_tenant_runtime transaction.
 */
final class LaravelF3CommittedWitnessObserver implements F3CommittedWitnessObserver
{
    public function __construct(
        private readonly TenantAuthorityBridge $bridge,
        private readonly TenantRuntimeConnectionProvider $connections,
        private readonly TenantRuntimeIdentityAttestor $identity,
        private readonly TenantAuthorityRevoker $revoker,
        private readonly RevokedTenantSessionVerifier $revokedSessions,
    ) {}

    public function observe(
        TenantHostContext $host,
        string $email,
        string $password,
        string $retryKey,
        Request $request,
        string $actorTenantId,
        string $observerMembershipId,
        string $adminMembershipId,
        string $ownWitnessId,
        string $foreignTenantId,
        string $foreignWitnessId,
        string $commitXid,
        int $fixtureBackendPid,
        string $runId,
    ): array {
        foreach ([$actorTenantId,$observerMembershipId,$adminMembershipId,$ownWitnessId,$foreignTenantId,$foreignWitnessId] as $uuid) {
            if (! Str::isUuid($uuid)) {
                throw new LogicException('F3 committed-witness identity is invalid.');
            }
        }
        if (! hash_equals($host->tenantId, $actorTenantId)
            || hash_equals($observerMembershipId, $adminMembershipId)
            || preg_match('/^\d+$/D', $commitXid) !== 1
            || $fixtureBackendPid < 1 || preg_match('/^[a-z0-9-]{8,64}$/D', $runId) !== 1) {
            throw new LogicException('F3 committed-witness contract is invalid.');
        }

        $connection = $this->connections->connection();
        if ($connection->transactionLevel() !== 0) {
            throw new LogicException('F3 committed-witness observer requires a fresh connection.');
        }
        $cleanupAuthority = null;
        $primary = null;
        $cleanupFailure = null;
        $result = null;
        $connection->beginTransaction();
        try {
            $connection->statement('SET TRANSACTION READ ONLY');
            $authority = $this->bridge->authenticateAndBind($host, $email, $password, $retryKey, $request);
            $cleanupAuthority = $request->attributes->get('tenant_staff_authority_cleanup');
            if (! hash_equals($observerMembershipId, $authority['context']->membershipId)
                || $request->attributes->get('tenant_staff_runtime_connection_id') !== spl_object_id($connection)
                || $this->connections->connection() !== $connection) {
                throw new LogicException('F3 observer authority is not independently bound.');
            }
            $identity = $this->identity->attest($connection);
            if ($identity['backend_pid'] === $fixtureBackendPid) {
                throw new LogicException('F3 observer reused the fixture backend.');
            }
            $own = $this->countWitness($connection, $actorTenantId, $ownWitnessId);
            $foreign = $this->countWitness($connection, $foreignTenantId, $foreignWitnessId);
            $visibility = $connection->selectOne(
                'SELECT pg_visible_in_snapshot(?::xid8, pg_current_snapshot()) AS commit_visible, pg_current_snapshot()::text AS snapshot, current_setting(\'transaction_read_only\')::text AS transaction_read_only',
                [$commitXid],
            );
            if ($own !== 1 || $foreign !== 0 || ! is_object($visibility)
                || ($visibility->commit_visible ?? null) !== true
                || ($visibility->transaction_read_only ?? null) !== 'on'
                || ! is_string($visibility->snapshot ?? null) || $visibility->snapshot === '') {
                throw new LogicException('F3 committed witness was not independently observed.');
            }
            $result = [
                'classification' => 'F3_COMMITTED_WITNESS_INDEPENDENTLY_OBSERVED',
                'run_id' => $runId,
                'actor_tenant_id' => $actorTenantId,
                'observer_membership_id' => $observerMembershipId,
                'own_witness_id' => $ownWitnessId,
                'own_witness_count' => $own,
                'foreign_witness_count' => $foreign,
                'commit_xid' => $commitXid,
                'commit_visible_in_snapshot' => true,
                'snapshot_fingerprint' => hash('sha256', $runId.'|'.$visibility->snapshot),
                'fixture_backend_pid' => $fixtureBackendPid,
                'observer_backend_pid' => $identity['backend_pid'],
                'runtime_principal' => $identity['principal'],
                'runtime_database' => $identity['database'],
                'runtime_system_identifier' => $identity['system_identifier'],
                'runtime_database_oid' => $identity['database_oid'],
                'observer_session_fingerprint' => hash('sha256', $runId.'|'.$request->session()->getId()),
                'authority_generation' => (string) $authority['authority_generation'],
                'transaction_read_only' => true,
                'observed_at' => now('UTC')->toIso8601String(),
            ];
        } catch (Throwable $exception) {
            $primary = $exception;
            throw $exception;
        } finally {
            try {
                if ($connection->transactionLevel() > 0) {
                    $connection->rollBack();
                }
                if (is_array($cleanupAuthority)) {
                    $this->revoker->revokeHash((string) ($cleanupAuthority['hash'] ?? ''), (string) ($cleanupAuthority['generation'] ?? ''));
                    $this->revokedSessions->assertDenied($host, $request, $connection);
                }
            } catch (Throwable $exception) {
                $cleanupFailure = $exception;
            } finally {
                Auth::guard('tenant_staff')->logout();
                $request->session()->flush();
                $request->attributes->remove('tenant_staff_context');
                $request->attributes->remove('tenant_staff_runtime_connection_id');
                $request->attributes->remove('tenant_staff_authority_cleanup');
            }
            if ($cleanupFailure !== null) {
                if ($primary !== null) {
                    throw new RestrictedTenantProbeCleanupException($primary::class, $cleanupFailure, $primary);
                }
                throw $cleanupFailure;
            }
        }
        if (! is_array($result)) {
            throw new LogicException('F3 committed-witness observer produced no result.');
        }
        $result['cleanup_status'] = 'COMPLETE';
        $result['revoked_session_denied'] = true;
        return $result;
    }

    private function countWitness(\Illuminate\Database\Connection $connection, string $tenantId, string $leadId): int
    {
        $row = $connection->selectOne(
            'SELECT count(*)::int AS aggregate FROM public.leads WHERE tenant_id=?::uuid AND id=?::uuid AND status=\'ACTIVE\' AND source=\'F3_ACCEPTANCE\'',
            [$tenantId,$leadId],
        );
        return is_object($row) && is_numeric($row->aggregate ?? null) ? (int) $row->aggregate : -1;
    }
}
