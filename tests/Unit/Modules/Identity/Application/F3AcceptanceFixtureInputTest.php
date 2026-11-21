<?php

declare(strict_types=1);

namespace Tests\Unit\Modules\Identity\Application;

use App\Modules\Identity\Application\F3AcceptanceFixtureInput;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class F3AcceptanceFixtureInputTest extends TestCase
{
    public function test_f02_accepts_distinct_strict_a_b_fixture_input(): void
    {
        $input = $this->valid();
        self::assertSame($input, (new F3AcceptanceFixtureInput)->validate($input, 'run-20261109-a01', 'dcrm_a01'));
    }

    #[DataProvider('invalidMutations')]
    public function test_f01_f05_f08_rejects_missing_mismatched_or_replayed_identity(callable $mutate): void
    {
        $input = $this->valid();
        $mutate($input);
        $this->expectException(InvalidArgumentException::class);
        (new F3AcceptanceFixtureInput)->validate($input, 'run-20261109-a01', 'dcrm_a01');
    }

    public static function invalidMutations(): array
    {
        return [
            'wrong run' => [static function (&$i): void { $i['run_id'] = 'old-run'; }],
            'wrong database' => [static function (&$i): void { $i['expected_database'] = 'daleel_local_dev'; }],
            'bad bootstrap proof' => [static function (&$i): void { $i['provider']['bootstrap_secret'] = 'bad'; }],
            'bad prewrite permit' => [static function (&$i): void { $i['permit_id'] = 'bad'; }],
            'same tenant slug' => [static function (&$i): void { $i['tenants']['B']['slug'] = $i['tenants']['A']['slug']; }],
            'same principal' => [static function (&$i): void { $i['tenants']['B']['admin_email'] = $i['tenants']['A']['admin_email']; }],
            'unexpected selector' => [static function (&$i): void { $i['tenant_id'] = 'forged'; }],
            'weak password' => [static function (&$i): void { $i['tenants']['A']['password'] = 'short'; }],
            'shared observer credential' => [static function (&$i): void { $i['tenants']['A']['observer_email'] = $i['tenants']['A']['admin_email']; }],
            'observer A collides with admin B' => [static function (&$i): void { $i['tenants']['A']['observer_email'] = $i['tenants']['B']['admin_email']; }],
            'observer B collides with admin A' => [static function (&$i): void { $i['tenants']['B']['observer_email'] = $i['tenants']['A']['admin_email']; }],
        ];
    }

    private function valid(): array
    {
        return [
            'run_id' => 'run-20261109-a01', 'expected_database' => 'dcrm_a01', 'permit_id' => str_repeat('b', 64),
            'provider' => ['bootstrap_secret' => str_repeat('a', 64),
                'email' => 'provider@example.invalid', 'password' => 'Strong!Provider123'],
            'tenants' => [
                'A' => ['display_name' => 'Fixture A', 'slug' => 'fixture-a01', 'timezone' => 'Africa/Cairo',
                    'admin_email' => 'admin-a@example.invalid', 'initial_password' => 'Initial!AdminA123',
                    'password' => 'Final!AdminA456', 'observer_email' => 'observer-a@example.invalid',
                    'observer_password' => 'Observe!AdminA789'],
                'B' => ['display_name' => 'Fixture B', 'slug' => 'fixture-b01', 'timezone' => 'Africa/Cairo',
                    'admin_email' => 'admin-b@example.invalid', 'initial_password' => 'Initial!AdminB123',
                    'password' => 'Final!AdminB456', 'observer_email' => 'observer-b@example.invalid',
                    'observer_password' => 'Observe!AdminB789'],
            ],
        ];
    }
}
