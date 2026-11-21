<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantStaffContext;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;
use Illuminate\Support\Str;
use LogicException;

/**
 * Fixed acceptance-only lead probes. No SQL, table, role, or tenant selector is
 * accepted from stdin or a public request. All mutations are rolled back by the
 * owning adapter after their in-transaction postcondition is observed.
 */
final class LaravelRestrictedTenantProbeExecutor implements RestrictedTenantProbeExecutor
{
    public function execute(Connection $connection, TenantStaffContext $context, RestrictedTenantProbePlan $plan): array
    {
        if ($connection->transactionLevel() < 1 || ! Str::isUuid($context->tenantId)
            || ! Str::isUuid($context->membershipId) || ! Str::isUuid($plan->targetTenantId)
            || ! Str::isUuid($plan->recordId)) {
            throw new LogicException('Restricted tenant probe runtime contract is invalid.');
        }

        $connection->statement('SAVEPOINT dcrm008_restricted_probe');
        $savepointReleased = false;
        try {
            $effects = match ($plan->operation) {
                'read' => $this->read($connection, $plan),
                'create' => $this->create($connection, $context, $plan),
                'update' => $this->update($connection, $plan),
                'delete' => $this->delete($connection, $plan),
            };
            $outcome = $effects === 0 && $plan->targetTenantId !== $context->tenantId
                ? 'DENIED_ZERO_ROWS'
                : 'ALLOWED';
        } catch (QueryException $exception) {
            $connection->statement('ROLLBACK TO SAVEPOINT dcrm008_restricted_probe');
            $connection->statement('RELEASE SAVEPOINT dcrm008_restricted_probe');
            $savepointReleased = true;
            if (($exception->errorInfo[0] ?? $exception->getCode()) !== '42501') {
                throw $exception;
            }
            $effects = 0;
            $outcome = 'DENIED_SQLSTATE_42501';
        }
        if (! $savepointReleased) {
            $connection->statement('RELEASE SAVEPOINT dcrm008_restricted_probe');
        }

        $postcondition = $this->read($connection, $plan);
        $proved = $outcome === 'ALLOWED'
            ? match ($plan->operation) {
                'create', 'update' => $postcondition === 1,
                'delete' => $postcondition === 0,
                'read' => $postcondition === $effects,
            }
            : $effects === 0 && $postcondition === 0;

        return [
            'attempted' => true,
            'executed' => true,
            'observed_outcome' => $outcome,
            'row_effects' => $effects,
            'postcondition_proved' => $proved,
        ];
    }

    private function read(Connection $connection, RestrictedTenantProbePlan $plan): int
    {
        $row = $connection->selectOne(
            'SELECT count(*)::int AS aggregate FROM public.leads WHERE tenant_id = ?::uuid AND id = ?::uuid',
            [$plan->targetTenantId, $plan->recordId],
        );

        return is_object($row) && is_numeric($row->aggregate ?? null) ? (int) $row->aggregate : 0;
    }

    private function create(Connection $connection, TenantStaffContext $context, RestrictedTenantProbePlan $plan): int
    {
        return $connection->affectingStatement(
            "INSERT INTO public.leads (id,tenant_id,name,pipeline_stage,status,created_by_membership_id,created_at,updated_at) VALUES (?::uuid,?::uuid,?,'new','ACTIVE',?::uuid,transaction_timestamp(),transaction_timestamp())",
            [$plan->recordId, $plan->targetTenantId, 'DCRM-008 '.$plan->caseId, $context->membershipId],
        );
    }

    private function update(Connection $connection, RestrictedTenantProbePlan $plan): int
    {
        return $connection->affectingStatement(
            'UPDATE public.leads SET name = ?, updated_at = transaction_timestamp() WHERE tenant_id = ?::uuid AND id = ?::uuid',
            ['DCRM-008 updated '.$plan->caseId, $plan->targetTenantId, $plan->recordId],
        );
    }

    private function delete(Connection $connection, RestrictedTenantProbePlan $plan): int
    {
        return $connection->affectingStatement(
            'DELETE FROM public.leads WHERE tenant_id = ?::uuid AND id = ?::uuid',
            [$plan->targetTenantId, $plan->recordId],
        );
    }
}
