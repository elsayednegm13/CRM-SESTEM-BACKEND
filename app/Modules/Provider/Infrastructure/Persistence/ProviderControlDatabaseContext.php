<?php

namespace App\Modules\Provider\Infrastructure\Persistence;

use Closure;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use LogicException;

/** Transaction-local identity and operation scope for the isolated control credential. */
final class ProviderControlDatabaseContext
{
    public function run(string $providerId, int $authVersion, int $stepUpAt, string $capability,
        string $mode, Closure $operation, ?string $operationId = null, ?string $approvalId = null,
        ?string $targetTenantId = null, ?string $action = null): mixed
    {
        foreach ([$providerId, $targetTenantId, $operationId, $approvalId] as $uuid) {
            if ($uuid !== null && ! Str::isUuid($uuid)) {
                throw new LogicException('Control-plane identifiers must be UUIDs.');
            }
        }
        if (! in_array($mode, ['PROVIDER_CONTROL', 'PROVIDER_CONTROL_REQUEST'], true)) {
            throw new LogicException('Invalid provider-control context mode.');
        }
        $connection = DB::connection('pgsql_provider_control');
        if ($connection->getDriverName() !== 'pgsql') {
            throw new LogicException('Provider control requires PostgreSQL.');
        }
        return $connection->transaction(function () use ($connection, $providerId, $authVersion,
            $stepUpAt, $capability, $mode, $operation, $operationId, $approvalId,
            $targetTenantId, $action): mixed {
            $values = [
                'app.context_mode' => $mode,
                'app.provider_user_id' => $providerId,
                'app.provider_auth_version' => (string) $authVersion,
                'app.provider_step_up_at' => gmdate('Y-m-d H:i:sP', $stepUpAt),
                'app.provider_capability' => $capability,
                'app.provider_operation_id' => $operationId ?? '',
                'app.provider_approval_id' => $approvalId ?? '',
                'app.provider_target_tenant_id' => $targetTenantId ?? '',
                'app.provider_action' => $action ?? '',
                'app.user_id' => '', 'app.tenant_id' => '', 'app.founder_invitation_id' => '',
            ];
            foreach ($values as $key => $value) {
                $connection->selectOne('SELECT set_config(?, ?, true)', [$key, $value]);
            }
            return $operation($connection);
        });
    }
}
