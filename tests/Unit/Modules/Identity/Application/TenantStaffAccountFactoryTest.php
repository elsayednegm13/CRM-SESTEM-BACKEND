<?php

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\TenantStaffAccountFactory;
use App\Modules\Identity\Domain\EmailAddressNormalizer;
use Illuminate\Support\Facades\Hash;
use InvalidArgumentException;
use Tests\TestCase;

final class TenantStaffAccountFactoryTest extends TestCase
{
    public function test_it_builds_a_tenant_local_argon2id_account_without_forced_rotation_or_persistence(): void
    {
        $password = 'A-strong-long-passphrase-482!';
        $payload = (new TenantStaffAccountFactory(new EmailAddressNormalizer()))->build(
            '019c4a5b-5010-7f00-8a00-50e6e64c335a',
            '  Admin@Example.COM ',
            '  Company Admin  ',
            $password,
        );

        self::assertSame('admin@example.com', $payload['canonical_email']);
        self::assertSame('Admin@Example.COM', $payload['display_email']);
        self::assertSame('Company Admin', $payload['display_name']);
        self::assertSame('ACTIVE', $payload['status']);
        self::assertSame(1, $payload['auth_version']);
        self::assertStringStartsWith('$argon2id$', $payload['password_hash']);
        self::assertTrue(Hash::driver('argon2id')->check($password, $payload['password_hash']));
        self::assertArrayNotHasKey('password', $payload);
        self::assertArrayNotHasKey('must_change_password', $payload);
    }

    public function test_equal_email_in_two_tenants_builds_distinct_tenant_owned_principals(): void
    {
        $factory = new TenantStaffAccountFactory(new EmailAddressNormalizer());
        $first = $factory->build(
            '019c4a5b-5010-7f00-8a00-50e6e64c335a',
            'Person@Example.com',
            'Person A',
            'A-strong-long-passphrase-482!',
        );
        $second = $factory->build(
            '019c4a5b-5010-7f00-8a00-50e6e64c335b',
            'person@example.com',
            'Person B',
            'Another-strong-long-passphrase-9!',
        );

        self::assertSame($first['canonical_email'], $second['canonical_email']);
        self::assertNotSame($first['tenant_id'], $second['tenant_id']);
        self::assertNotSame($first['id'], $second['id']);
        self::assertNotSame($first['password_hash'], $second['password_hash']);
    }

    public function test_it_rejects_passwords_outside_the_existing_quality_and_byte_limits(): void
    {
        $factory = new TenantStaffAccountFactory(new EmailAddressNormalizer());

        foreach (['short', str_repeat('a', 1025)] as $password) {
            try {
                $factory->build(
                    '019c4a5b-5010-7f00-8a00-50e6e64c335a',
                    'person@example.com',
                    'Person',
                    $password,
                );
                self::fail('Expected an invalid initial password to be rejected.');
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }
}
