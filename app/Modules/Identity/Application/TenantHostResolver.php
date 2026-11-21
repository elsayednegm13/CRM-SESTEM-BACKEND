<?php

namespace App\Modules\Identity\Application;

use App\Modules\Identity\Domain\TenantHostContext;
use App\Modules\Provider\Domain\CanonicalTenantHost;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use InvalidArgumentException;

final class TenantHostResolver
{
    public function resolve(string $requestHost): TenantHostContext
    {
        $baseDomain = config('tenancy.base_domain');
        if (! is_string($baseDomain) || $baseDomain === '') {
            throw new InvalidArgumentException('Tenant host resolution is not configured.');
        }

        $environmentScope = $this->environmentScope($baseDomain);
        $this->assertConnectionConfigured('pgsql_hostname_resolver');
        $host = strtolower($requestHost);
        if ($host !== $requestHost || strlen($host) > 253 || filter_var($host, FILTER_VALIDATE_IP) !== false
            || str_contains($host, ':') || str_ends_with($host, '.')) {
            throw new InvalidArgumentException('The request host is not canonical.');
        }

        $suffix = '.'.$baseDomain;
        if (! str_ends_with($host, $suffix)) {
            throw new InvalidArgumentException('The request host is outside the configured tenant domain.');
        }

        $slug = substr($host, 0, -strlen($suffix));
        if ($slug === '' || str_contains($slug, '.')) {
            throw new InvalidArgumentException('Only canonical platform tenant hosts are supported.');
        }

        $canonical = CanonicalTenantHost::forSlug(
            $slug,
            $baseDomain,
            (string) config('app.env'),
            (bool) config('tenancy.allow_localhost_base_domain'),
            is_string(config('tenancy.local_test_base_domain')) ? config('tenancy.local_test_base_domain') : null,
        );
        if (! hash_equals($canonical->value(), $host)) {
            throw new InvalidArgumentException('The request host does not match a canonical tenant hostname.');
        }

        /** @var Connection $connection */
        $connection = DB::connection('pgsql_hostname_resolver');
        $mapping = $connection->transaction(function () use ($connection, $host, $baseDomain, $environmentScope): ?object {
            $connection->selectOne("SELECT set_config('app.context_mode', 'HOST_RESOLUTION', true)");
            $connection->selectOne("SELECT set_config('app.host_resolution_hostname', ?, true)", [$host]);

            return $connection->selectOne(<<<'SQL'
                SELECT h.tenant_id, h.tenant_slug, h.hostname, h.base_domain, d.environment_scope
                FROM public.tenant_hostnames h
                JOIN public.tenant_registry_domains d
                  ON d.mapping_version = h.mapping_version
                 AND d.base_domain = h.base_domain
                WHERE h.hostname = ?
                  AND h.base_domain = ?
                  AND d.environment_scope = ?
                  AND d.is_active
            SQL, [$host, $baseDomain, $environmentScope]);
        });

        if (! $mapping
            || $mapping->hostname !== $host
            || $mapping->base_domain !== $baseDomain
            || $mapping->environment_scope !== $environmentScope
            || ! Str::isUuid((string) $mapping->tenant_id)) {
            throw new InvalidArgumentException('No active tenant host mapping is available.');
        }

        return new TenantHostContext(
            $mapping->tenant_id,
            $mapping->tenant_slug,
            $mapping->hostname,
            $mapping->base_domain,
            $mapping->environment_scope,
        );
    }

    private function environmentScope(string $baseDomain): string
    {
        if (str_ends_with($baseDomain, '.localhost')) {
            if (! in_array(config('app.env'), ['local', 'testing'], true)
                || config('tenancy.allow_localhost_base_domain') !== true
                || config('tenancy.local_test_base_domain') !== $baseDomain) {
                throw new InvalidArgumentException('Local tenant hostnames are not enabled for this environment.');
            }

            return 'LOCAL_TEST';
        }

        return 'NON_LOCAL';
    }

    private function assertConnectionConfigured(string $name): void
    {
        $configuration = config('database.connections.'.$name);
        foreach (['host', 'database', 'username', 'password'] as $key) {
            if (! is_array($configuration) || ! is_string($configuration[$key] ?? null) || trim($configuration[$key]) === '') {
                throw new InvalidArgumentException('The tenant hostname resolver connection is not configured.');
            }
        }
    }
}
