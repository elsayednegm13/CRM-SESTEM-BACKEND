<?php

namespace App\Modules\Provider\Infrastructure\Persistence;

use Closure;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

/** Transaction-local provider audit identity on the provider credential only. */
final class ProviderDatabaseContext
{
    public function run(string $serverProviderId, Closure $operation, ?string $targetTenantId = null): mixed
    {
        if (! Str::isUuid($serverProviderId)) {
            throw new LogicException('Provider identity must be server-derived UUID.');
        }
        if ($targetTenantId !== null && ! Str::isUuid($targetTenantId)) {
            throw new LogicException('Target tenant identity must be a UUID.');
        }
        $connection = DB::connection('pgsql_provider');
        if ($connection->getDriverName() !== 'pgsql') {
            throw new LogicException('Provider mutation requires PostgreSQL.');
        }
        $nested = $connection->transactionLevel() > 0;

        return $connection->transaction(function () use ($connection, $serverProviderId, $operation, $nested, $targetTenantId): mixed {
            $keys = ['app.context_mode', 'app.provider_user_id', 'app.user_id', 'app.tenant_id'];
            $previous = [];
            foreach ($keys as $key) {
                $previous[$key] = $connection->selectOne('SELECT current_setting(?, true) AS value', [$key])->value;
                $connection->selectOne('SELECT set_config(?, ?, true) AS value', [$key, '']);
            }
            $connection->selectOne('SELECT set_config(?, ?, true) AS value', ['app.provider_user_id', $serverProviderId]);
            $connection->selectOne('SELECT set_config(?, ?, true) AS value', ['app.context_mode', 'PROVIDER']);
            if ($targetTenantId !== null) {
                $connection->selectOne('SELECT set_config(?, ?, true) AS value', ['app.tenant_id', $targetTenantId]);
            }

            $completed = false;
            try {
                $result = $operation($connection);
                $completed = true;
                return $result;
            } finally {
                // On a failed nested savepoint PostgreSQL rollback restores SET LOCAL.
                if ($nested && $completed) {
                    foreach ($keys as $key) {
                        $connection->selectOne('SELECT set_config(?, ?, true) AS value', [$key, $previous[$key] ?? '']);
                    }
                }
            }
        });
    }
}
