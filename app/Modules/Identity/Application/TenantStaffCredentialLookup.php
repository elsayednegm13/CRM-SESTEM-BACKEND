<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use LogicException;
use Illuminate\Support\Facades\DB;

final class TenantStaffCredentialLookup
{
    /** @return object|null Credential data is returned only by the restricted pre-auth function. */
    public function forHostAndEmail(TenantHostContext $host, string $canonicalEmail): ?object
    {
        $configuration = config('database.connections.pgsql_tenant_auth');
        foreach (['host', 'database', 'username', 'password'] as $key) {
            if (! is_array($configuration) || ! is_string($configuration[$key] ?? null) || trim($configuration[$key]) === '') {
                throw new LogicException('The tenant authentication connection is not configured.');
            }
        }

        $connection = DB::connection('pgsql_tenant_auth');

        return $connection->selectOne(
            'SELECT * FROM public.lookup_tenant_staff_credentials(?, ?, ?, ?)',
            [$host->hostname, $host->baseDomain, $host->environmentScope, $canonicalEmail],
        );
    }
}
