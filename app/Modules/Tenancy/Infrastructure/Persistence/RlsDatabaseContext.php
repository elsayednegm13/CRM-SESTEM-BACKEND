<?php

namespace App\Modules\Tenancy\Infrastructure\Persistence;

use App\Modules\Tenancy\Domain\TenantAccessException;
use App\Modules\Tenancy\Domain\TenantContext;
use Closure;
use Illuminate\Support\Facades\DB;

/** The only application entry point for transaction-local PostgreSQL RLS context. */
final class RlsDatabaseContext
{
    public function discoverForUser(string $serverUserId, Closure $operation): mixed
    {
        $this->requireUuid($serverUserId);

        return $this->scoped(function () use ($serverUserId, $operation): mixed {
            $this->set('app.user_id', $serverUserId);
            $this->set('app.context_mode', 'TENANT_DISCOVERY');

            return $operation($this);
        });
    }

    /** Only a membership visible under discovery may select the tenant. */
    public function activateFromMembership(string $serverUserId, string $membershipId): string
    {
        $this->requireUuid($serverUserId);
        $this->requireUuid($membershipId);
        if (DB::transactionLevel() < 1 || $this->setting('app.context_mode') !== 'TENANT_DISCOVERY'
            || $this->setting('app.user_id') !== $serverUserId) {
            throw TenantAccessException::contextRequired();
        }

        $membership = DB::table('tenant_memberships')->where('id', $membershipId)
            ->where('user_id', $serverUserId)->where('status', 'ACTIVE')->first(['tenant_id']);
        if (! $membership) {
            throw TenantAccessException::membershipRequired();
        }

        $this->set('app.tenant_id', $membership->tenant_id);
        $this->set('app.context_mode', TenantContext::MODE);

        return $membership->tenant_id;
    }

    public function forTenant(TenantContext $context, Closure $operation): mixed
    {
        if ($context->mode !== TenantContext::MODE) {
            throw TenantAccessException::contextRequired();
        }
        $this->requireUuid($context->userId);
        $this->requireUuid($context->tenantId);

        return $this->scoped(function () use ($context, $operation): mixed {
            $this->set('app.user_id', $context->userId);
            $this->set('app.tenant_id', $context->tenantId);
            $this->set('app.context_mode', TenantContext::MODE);

            return $operation();
        });
    }

    private function scoped(Closure $operation): mixed
    {
        $nested = DB::transactionLevel() > 0;

        return DB::transaction(function () use ($operation, $nested): mixed {
            $keys = ['app.context_mode', 'app.user_id', 'app.tenant_id'];
            $previous = [];
            foreach ($keys as $key) {
                $previous[$key] = $this->setting($key);
                $this->set($key, '');
            }

            $completed = false;
            try {
                $result = $operation();
                $completed = true;
                return $result;
            } finally {
                // A released savepoint does not end an outer transaction's SET LOCAL scope.
                // On failure PostgreSQL first rolls back the savepoint, which restores
                // prior SET LOCAL values; issuing SQL in the aborted scope would mask
                // the original error with 25P02.
                if ($nested && $completed) {
                    foreach ($keys as $key) {
                        $this->set($key, $previous[$key] ?? '');
                    }
                }
            }
        });
    }

    private function setting(string $key): ?string
    {
        $row = DB::selectOne('SELECT current_setting(?, true) AS value', [$key]);

        return $row->value ?? null;
    }

    private function set(string $key, string $value): void
    {
        DB::selectOne('SELECT set_config(?, ?, true) AS value', [$key, $value]);
    }

    private function requireUuid(string $value): void
    {
        if (! preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/D', $value)) {
            throw TenantAccessException::contextRequired();
        }
    }
}
