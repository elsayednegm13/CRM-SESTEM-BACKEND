<?php

namespace Tests\Unit\Modules\Identity\Domain;

use App\Modules\Identity\Application\TenantHostResolver;
use InvalidArgumentException;
use Tests\TestCase;

final class TenantHostContextTest extends TestCase
{
    public function test_reserved_realm_names_are_not_parsed_as_tenant_hosts(): void
    {
        config([
            'app.env' => 'testing',
            'tenancy.base_domain' => 'id02.localhost',
            'tenancy.allow_localhost_base_domain' => true,
            'tenancy.local_test_base_domain' => 'id02.localhost',
        ]);

        foreach (['api.id02.localhost', 'marketing.id02.localhost', 'superadmin.id02.localhost'] as $host) {
            try {
                app(TenantHostResolver::class)->resolve($host);
                self::fail("Reserved or unregistered realm {$host} must be rejected before database access.");
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_localhost_mapping_requires_explicit_local_test_configuration(): void
    {
        config([
            'app.env' => 'production',
            'tenancy.base_domain' => 'id02.localhost',
            'tenancy.allow_localhost_base_domain' => true,
            'tenancy.local_test_base_domain' => 'id02.localhost',
        ]);

        $this->expectException(InvalidArgumentException::class);
        app(TenantHostResolver::class)->resolve('company-a.id02.localhost');
    }

    public function test_ip_literal_unrelated_domain_and_malformed_hosts_fail_before_database_access(): void
    {
        config([
            'app.env' => 'testing',
            'tenancy.base_domain' => 'id02.localhost',
            'tenancy.allow_localhost_base_domain' => true,
            'tenancy.local_test_base_domain' => 'id02.localhost',
        ]);

        foreach (['127.0.0.1', 'company-a.example.test', 'Company-A.id02.localhost', 'company-a.extra.id02.localhost', 'company-a.id02.localhost.'] as $host) {
            try {
                app(TenantHostResolver::class)->resolve($host);
                self::fail("Malformed host {$host} must be rejected before database access.");
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }
}
