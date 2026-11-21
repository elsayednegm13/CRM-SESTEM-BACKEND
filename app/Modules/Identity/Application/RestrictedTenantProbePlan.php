<?php
declare(strict_types=1);
namespace App\Modules\Identity\Application;

use InvalidArgumentException;

/** Immutable acceptance plan; no caller-controlled SQL, role, or tenant selector. */
final readonly class RestrictedTenantProbePlan
{
    public function __construct(
        public string $runId,
        public string $caseId,
        public string $actorTenantId,
        public string $operation,
        public string $connectionId,
        public string $transactionId,
        public string $targetTenantId = '',
        public string $recordId = '',
        public string $expectedOutcome = 'ALLOWED',
        public ?int $expectedRowEffects = null,
    )
    {
        if ($runId === '' || $caseId === '' || ! in_array($operation, ['read','create','update','delete'], true)
            || $connectionId === '' || $transactionId === ''
            || ! in_array($expectedOutcome, ['ALLOWED','DENIED_ZERO_ROWS','DENIED_SQLSTATE_42501'], true)
            || ($expectedRowEffects !== null && $expectedRowEffects < 0)) {
            throw new InvalidArgumentException('Restricted tenant probe plan is invalid.');
        }
    }
}
