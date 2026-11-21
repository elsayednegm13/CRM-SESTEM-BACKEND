<?php

namespace App\Modules\Provider\Infrastructure\Persistence;

use App\Modules\Provider\Domain\CanonicalTenantHost;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Str;
use DomainException;
use LogicException;

/**
 * Persistence primitive for the existing Provider approval transaction.
 * Callers must pass its pgsql_provider_control connection; PostgreSQL RLS is
 * the authority for whether the active approved operation may insert a row.
 */
final class TenantHostnameRegistry
{
    public function register(ConnectionInterface $connection, string $tenantId, string $slug): void
    {
        if (! method_exists($connection, 'getName') || $connection->getName() !== 'pgsql_provider_control') {
            throw new LogicException('Tenant host registration requires the Provider control transaction.');
        }

        if (! Str::isUuid($tenantId)) {
            throw new LogicException('Tenant host registration requires a tenant UUID.');
        }

        $baseDomain = config('tenancy.base_domain');
        $localTestBaseDomain = config('tenancy.local_test_base_domain');
        $host = CanonicalTenantHost::forSlug(
            $slug,
            is_string($baseDomain) ? $baseDomain : null,
            (string) config('app.env', 'production'),
            (bool) config('tenancy.allow_localhost_base_domain', false),
            is_string($localTestBaseDomain) ? $localTestBaseDomain : null,
        );

        $expected = [
            'tenant_id' => $tenantId,
            'tenant_slug' => $host->slug(),
            'base_domain' => $host->baseDomain(),
            'hostname' => $host->value(),
            'mapping_version' => 1,
        ];
        $stored = $connection->table('tenant_hostnames')->where('tenant_id', $tenantId)->first([
            'tenant_id', 'tenant_slug', 'base_domain', 'hostname', 'mapping_version',
        ]);
        if ($stored !== null) {
            $this->assertSameReservation($stored, $expected);

            return;
        }

        $connection->table('tenant_hostnames')->insertOrIgnore($expected);
        $stored = $connection->table('tenant_hostnames')->where('tenant_id', $tenantId)->first([
            'tenant_id', 'tenant_slug', 'base_domain', 'hostname', 'mapping_version',
        ]);
        if ($stored === null) {
            throw new DomainException('The tenant hostname reservation conflicts with an existing mapping.');
        }

        $this->assertSameReservation($stored, $expected);
    }

    /** @param array<string, string|int> $expected */
    private function assertSameReservation(object $stored, array $expected): void
    {
        foreach ($expected as $column => $value) {
            if ((string) $stored->{$column} !== (string) $value) {
                throw new DomainException('The tenant hostname reservation conflicts with an existing mapping.');
            }
        }
    }
}
