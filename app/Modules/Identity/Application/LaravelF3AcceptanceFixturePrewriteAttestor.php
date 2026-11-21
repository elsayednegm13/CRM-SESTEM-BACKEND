<?php

declare(strict_types=1);

namespace App\Modules\Identity\Application;

use LogicException;

/** Prewrite binding to the restricted runtime connection and private owner permit. */
final class LaravelF3AcceptanceFixturePrewriteAttestor implements F3AcceptanceFixturePrewriteAttestor
{
    public function __construct(
        private readonly TenantRuntimeConnectionProvider $connections,
        private readonly TenantRuntimeIdentityAttestor $identity,
    ) {}

    public function attest(string $runId, string $permitId): void
    {
        $configuredPermit = config('f3_acceptance.fixture_permit_id');
        $permitPath = config('f3_acceptance.fixture_permit_path');
        if (! is_string($configuredPermit) || preg_match('/^[a-f0-9]{64}$/D', $configuredPermit) !== 1
            || ! hash_equals($configuredPermit, $permitId)
            || ! is_string($permitPath) || $permitPath !== '/run/f3/fixture-permit.json'
            || ! is_file($permitPath)) {
            throw new LogicException('F3 fixture prewrite permit is unavailable.');
        }
        try {
            $permit = json_decode((string) file_get_contents($permitPath), true, 16, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            throw new LogicException('F3 fixture prewrite permit is malformed.');
        }
        $expected = [
            'run_id' => $runId,
            'permit_id' => $permitId,
            'database' => config('f3_acceptance.expected_database'),
            'system_identifier' => config('f3_acceptance.expected_system_identifier'),
            'database_oid' => config('f3_acceptance.expected_database_oid'),
            'principal' => config('f3_acceptance.expected_runtime_principal'),
        ];
        if (! is_array($permit) || array_keys($permit) !== array_keys($expected)) {
            throw new LogicException('F3 fixture prewrite permit shape is invalid.');
        }
        foreach ($expected as $key => $value) {
            if (! is_string($value) || ! is_string($permit[$key] ?? null) || ! hash_equals($value, $permit[$key])) {
                throw new LogicException('F3 fixture prewrite permit binding is invalid.');
            }
        }
        $connection = $this->connections->connection();
        if ($connection->transactionLevel() !== 0) {
            throw new LogicException('F3 fixture prewrite transaction state is invalid.');
        }
        $connection->beginTransaction();
        try {
            $this->identity->attest($connection);
        } finally {
            if ($connection->transactionLevel() > 0) {
                $connection->rollBack();
            }
        }
    }
}
