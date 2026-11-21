<?php

namespace Tests\Unit\Modules\Provider\Domain;

use App\Modules\Provider\Domain\CanonicalTenantHost;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class CanonicalTenantHostTest extends TestCase
{
    public function test_it_derives_a_canonical_platform_host_from_explicit_configuration(): void
    {
        $host = CanonicalTenantHost::forSlug('acme-north', 'example.test');

        self::assertSame('acme-north', $host->slug());
        self::assertSame('example.test', $host->baseDomain());
        self::assertSame('acme-north.example.test', $host->value());
    }

    public function test_it_does_not_supply_a_domain_when_configuration_is_absent(): void
    {
        $this->expectException(InvalidArgumentException::class);

        CanonicalTenantHost::forSlug('acme', null);
    }

    public function test_it_rejects_reserved_tenant_labels(): void
    {
        $this->expectException(InvalidArgumentException::class);

        CanonicalTenantHost::forSlug('superadmin', 'example.test');
    }

    public function test_it_accepts_the_exact_local_test_base_only_with_both_local_gates(): void
    {
        foreach (['local', 'testing'] as $environment) {
            $host = CanonicalTenantHost::forSlug(
                'company-a',
                'daleel.localhost',
                $environment,
                true,
                'daleel.localhost',
            );

            self::assertSame('company-a.daleel.localhost', $host->value());
        }
    }

    public function test_it_rejects_localhost_bases_without_both_gates_or_outside_local_test(): void
    {
        foreach ([
            ['local', false, 'daleel.localhost', 'daleel.localhost'],
            ['production', true, 'daleel.localhost', 'daleel.localhost'],
            ['staging', true, 'daleel.localhost', 'daleel.localhost'],
            ['testing', true, 'foo.localhost', 'daleel.localhost'],
            ['local', true, 'foo.other.localhost', 'daleel.localhost'],
            ['local', true, 'localhost', 'localhost'],
        ] as [$environment, $allowLocalhost, $baseDomain, $localTestBaseDomain]) {
            try {
                CanonicalTenantHost::forSlug(
                    'company-a',
                    $baseDomain,
                    $environment,
                    $allowLocalhost,
                    $localTestBaseDomain,
                );
                self::fail("Expected {$baseDomain} to be rejected in {$environment}.");
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_it_rejects_reserved_service_labels_with_the_local_test_base(): void
    {
        foreach (['api', 'superadmin'] as $reservedSlug) {
            try {
                CanonicalTenantHost::forSlug(
                    $reservedSlug,
                    'daleel.localhost',
                    'testing',
                    true,
                    'daleel.localhost',
                );
                self::fail("Expected {$reservedSlug} to remain reserved.");
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function test_regular_synthetic_test_base_does_not_need_the_localhost_exception(): void
    {
        $host = CanonicalTenantHost::forSlug('company-a', 'example.test', 'testing');

        self::assertSame('company-a.example.test', $host->value());
    }

    public function test_it_rejects_noncanonical_or_unsafe_slug_and_domain_inputs(): void
    {
        foreach ([
            ['Acme', 'example.test'],
            ['-acme', 'example.test'],
            ['acme-', 'example.test'],
            ['acme', 'Example.test'],
            ['acme', 'example.test.'],
            ['acme', 'https://example.test'],
            ['acme', 'example.test:8443'],
            ['acme', '127.0.0.1'],
            ['acme', 'localhost'],
            ['acme', 'example.123'],
            ['acme', 'exämple.test'],
        ] as [$slug, $baseDomain]) {
            try {
                CanonicalTenantHost::forSlug($slug, $baseDomain);
                self::fail("Expected canonical host validation to reject {$slug}@{$baseDomain}.");
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }
}
