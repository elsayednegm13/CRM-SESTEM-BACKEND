<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\Exceptions\RestrictedTenantProbeCleanupException;
use App\Modules\Identity\Domain\TenantHostContext;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use LogicException;
use Throwable;

/**
 * Acceptance-only future-live adapter. It is not container-bound and has no
 * route. The caller must supply a normal Laravel request/session and the real
 * TenantStaffLoginService through TenantAuthorityBridge.
 */
final class LaravelRestrictedTenantRuntimeAdapter
{
    public function __construct(
        private readonly TenantAuthorityBridge $bridge,
        private readonly TenantRuntimeConnectionProvider $connections,
        private readonly RestrictedTenantProbeExecutor $probes,
        private readonly TenantAuthorityRevoker $revoker,
        private readonly TenantRuntimeIdentityAttestor $identity,
        private readonly RevokedTenantSessionVerifier $revokedSessions,
    ) {}

    /** @return array<string,mixed> */
    public function authenticateAndExecute(
        TenantHostContext $host,
        string $email,
        string $password,
        string $retryKey,
        Request $request,
        RestrictedTenantProbePlan $plan,
    ): array {
        if (! hash_equals($host->tenantId, $plan->actorTenantId)) {
            throw new LogicException('Restricted tenant probe actor/tenant mismatch.');
        }

        $connection = $this->connections->connection();
        if ($connection->transactionLevel() !== 0) {
            throw new LogicException('Restricted tenant probe requires an unowned runtime connection.');
        }

        $primary = null;
        $cleanupFailure = null;
        $cleanupAuthority = null;
        $result = null;
        $connection->beginTransaction();
        try {
            $authority = $this->bridge->authenticateAndBind($host, $email, $password, $retryKey, $request);
            $cleanupAuthority = $request->attributes->get('tenant_staff_authority_cleanup');
            $boundConnection = $request->attributes->get('tenant_staff_runtime_connection_id');
            if (! is_int($boundConnection) || $boundConnection !== spl_object_id($connection)
                || $this->connections->connection() !== $connection || $connection->transactionLevel() < 1) {
                throw new LogicException('Restricted tenant probe connection affinity was not proved.');
            }

            $identity = $this->identity->attest($connection);
            $observation = $this->probes->execute($connection, $authority['context'], $plan);
            $this->assertObservation($observation, $plan);

            $result = array_merge($observation, [
                'classification' => 'ADAPTER_OBSERVATION_REQUIRES_INDEPENDENT_VERIFICATION',
                'run_id' => $plan->runId,
                'case_id' => $plan->caseId,
                'operation' => $plan->operation,
                'expected_outcome' => $plan->expectedOutcome,
                'expected_row_effects' => $plan->expectedRowEffects,
                'actor_tenant_id' => $plan->actorTenantId,
                'target_tenant_id' => $plan->targetTenantId,
                'connection_object_id' => spl_object_id($connection),
                'runtime_principal' => $identity['principal'],
                'runtime_database' => $identity['database'],
                'runtime_system_identifier' => $identity['system_identifier'],
                'runtime_database_oid' => $identity['database_oid'],
                'runtime_backend_pid' => $identity['backend_pid'],
                // A run-bound digest proves distinct fresh Laravel sessions
                // without exposing a reusable session identifier in evidence.
                'observer_session_fingerprint' => hash('sha256', $plan->runId.'|'.$request->session()->getId()),
                'authority_generation' => (string) $authority['authority_generation'],
                'observed_at' => now('UTC')->toIso8601String(),
            ]);
        } catch (Throwable $exception) {
            $primary = $exception;
            throw $exception;
        } finally {
            try {
                if ($connection->transactionLevel() > 0) {
                    $connection->rollBack();
                }
                if ($connection->transactionLevel() !== 0) {
                    throw new LogicException('Restricted tenant probe transaction cleanup is incomplete.');
                }
                if (is_array($cleanupAuthority)) {
                    $this->revoker->revokeHash(
                        (string) ($cleanupAuthority['hash'] ?? ''),
                        (string) ($cleanupAuthority['generation'] ?? ''),
                    );
                    $this->revokedSessions->assertDenied($host, $request, $connection);
                }
            } catch (Throwable $exception) {
                $cleanupFailure = $exception;
            } finally {
                Auth::guard('tenant_staff')->logout();
                $request->session()->forget('identity.tenant_staff');
                $request->session()->forget('identity.tenant_authority_generation');
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
            throw new LogicException('Restricted tenant probe produced no result.');
        }

        $result['cleanup_status'] = 'COMPLETE';
        $result['revoked_session_denied'] = true;

        return $result;
    }

    /** @param array<string,mixed> $observation */
    private function assertObservation(array $observation, RestrictedTenantProbePlan $plan): void
    {
        if (($observation['attempted'] ?? null) !== true || ($observation['executed'] ?? null) !== true
            || ($observation['postcondition_proved'] ?? null) !== true
            || ! is_int($observation['row_effects'] ?? null)
            || ! is_string($observation['observed_outcome'] ?? null)
            || $observation['observed_outcome'] !== $plan->expectedOutcome
            || ($plan->expectedRowEffects !== null && $observation['row_effects'] !== $plan->expectedRowEffects)
            || ($plan->operation !== 'read' && $plan->expectedOutcome === 'ALLOWED' && $observation['row_effects'] < 1)) {
            throw new LogicException('Restricted tenant probe evidence is incomplete or unexpected.');
        }
    }
}
